rule TTP_XOR_QUAD_CurrentVersionRun_0307 {
  strings:
    $key_0307 = { 50 68 [2] 74 66 [2] 5f 4a [2] 71 68 [2] 65 73 [2] 6a 69 [2] 74 74 [2] 76 75 [2] 6d 73 [2] 71 74 [2] 6d 5b }

  condition:
    any of them
}