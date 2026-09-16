rule TTP_XOR_QUAD_CurrentVersionRun_1625 {
  strings:
    $key_1625 = { 45 4a [2] 61 44 [2] 4a 68 [2] 64 4a [2] 70 51 [2] 7f 4b [2] 61 56 [2] 63 57 [2] 78 51 [2] 64 56 [2] 78 79 }

  condition:
    any of them
}