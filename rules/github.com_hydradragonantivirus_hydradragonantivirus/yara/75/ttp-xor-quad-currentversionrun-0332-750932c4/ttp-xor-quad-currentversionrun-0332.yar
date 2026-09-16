rule TTP_XOR_QUAD_CurrentVersionRun_0332 {
  strings:
    $key_0332 = { 50 5d [2] 74 53 [2] 5f 7f [2] 71 5d [2] 65 46 [2] 6a 5c [2] 74 41 [2] 76 40 [2] 6d 46 [2] 71 41 [2] 6d 6e }

  condition:
    any of them
}