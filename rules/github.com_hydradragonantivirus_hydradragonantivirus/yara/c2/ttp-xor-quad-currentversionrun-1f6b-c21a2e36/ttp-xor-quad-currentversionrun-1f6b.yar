rule TTP_XOR_QUAD_CurrentVersionRun_1f6b {
  strings:
    $key_1f6b = { 4c 04 [2] 68 0a [2] 43 26 [2] 6d 04 [2] 79 1f [2] 76 05 [2] 68 18 [2] 6a 19 [2] 71 1f [2] 6d 18 [2] 71 37 }

  condition:
    any of them
}