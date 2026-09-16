rule TTP_XOR_QUAD_CurrentVersionRun_0432 {
  strings:
    $key_0432 = { 57 5d [2] 73 53 [2] 58 7f [2] 76 5d [2] 62 46 [2] 6d 5c [2] 73 41 [2] 71 40 [2] 6a 46 [2] 76 41 [2] 6a 6e }

  condition:
    any of them
}