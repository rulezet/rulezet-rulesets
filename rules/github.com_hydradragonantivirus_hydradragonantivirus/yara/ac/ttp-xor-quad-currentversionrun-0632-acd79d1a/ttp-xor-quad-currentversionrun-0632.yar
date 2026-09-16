rule TTP_XOR_QUAD_CurrentVersionRun_0632 {
  strings:
    $key_0632 = { 55 5d [2] 71 53 [2] 5a 7f [2] 74 5d [2] 60 46 [2] 6f 5c [2] 71 41 [2] 73 40 [2] 68 46 [2] 74 41 [2] 68 6e }

  condition:
    any of them
}