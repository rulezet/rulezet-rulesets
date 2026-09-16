rule TTP_XOR_QUAD_CurrentVersionRun_1f24 {
  strings:
    $key_1f24 = { 4c 4b [2] 68 45 [2] 43 69 [2] 6d 4b [2] 79 50 [2] 76 4a [2] 68 57 [2] 6a 56 [2] 71 50 [2] 6d 57 [2] 71 78 }

  condition:
    any of them
}