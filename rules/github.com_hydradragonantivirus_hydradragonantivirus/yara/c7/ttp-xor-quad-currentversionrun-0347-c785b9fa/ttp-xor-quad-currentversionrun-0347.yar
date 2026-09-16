rule TTP_XOR_QUAD_CurrentVersionRun_0347 {
  strings:
    $key_0347 = { 50 28 [2] 74 26 [2] 5f 0a [2] 71 28 [2] 65 33 [2] 6a 29 [2] 74 34 [2] 76 35 [2] 6d 33 [2] 71 34 [2] 6d 1b }

  condition:
    any of them
}