rule TTP_XOR_QUAD_CurrentVersionRun_3117 {
  strings:
    $key_3117 = { 62 78 [2] 46 76 [2] 6d 5a [2] 43 78 [2] 57 63 [2] 58 79 [2] 46 64 [2] 44 65 [2] 5f 63 [2] 43 64 [2] 5f 4b }

  condition:
    any of them
}