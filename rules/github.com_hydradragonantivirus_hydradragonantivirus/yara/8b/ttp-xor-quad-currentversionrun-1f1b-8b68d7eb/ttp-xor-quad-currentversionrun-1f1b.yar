rule TTP_XOR_QUAD_CurrentVersionRun_1f1b {
  strings:
    $key_1f1b = { 4c 74 [2] 68 7a [2] 43 56 [2] 6d 74 [2] 79 6f [2] 76 75 [2] 68 68 [2] 6a 69 [2] 71 6f [2] 6d 68 [2] 71 47 }

  condition:
    any of them
}