rule TTP_XOR_QUAD_CurrentVersionRun_1f17 {
  strings:
    $key_1f17 = { 4c 78 [2] 68 76 [2] 43 5a [2] 6d 78 [2] 79 63 [2] 76 79 [2] 68 64 [2] 6a 65 [2] 71 63 [2] 6d 64 [2] 71 4b }

  condition:
    any of them
}