rule TTP_XOR_QUAD_CurrentVersionRun_1f0b {
  strings:
    $key_1f0b = { 4c 64 [2] 68 6a [2] 43 46 [2] 6d 64 [2] 79 7f [2] 76 65 [2] 68 78 [2] 6a 79 [2] 71 7f [2] 6d 78 [2] 71 57 }

  condition:
    any of them
}