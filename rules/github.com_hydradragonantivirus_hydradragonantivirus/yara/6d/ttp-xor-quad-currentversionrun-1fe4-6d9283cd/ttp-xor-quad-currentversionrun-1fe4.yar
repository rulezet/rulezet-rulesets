rule TTP_XOR_QUAD_CurrentVersionRun_1fe4 {
  strings:
    $key_1fe4 = { 4c 8b [2] 68 85 [2] 43 a9 [2] 6d 8b [2] 79 90 [2] 76 8a [2] 68 97 [2] 6a 96 [2] 71 90 [2] 6d 97 [2] 71 b8 }

  condition:
    any of them
}