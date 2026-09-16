rule TTP_XOR_QUAD_CurrentVersionRun_1f05 {
  strings:
    $key_1f05 = { 4c 6a [2] 68 64 [2] 43 48 [2] 6d 6a [2] 79 71 [2] 76 6b [2] 68 76 [2] 6a 77 [2] 71 71 [2] 6d 76 [2] 71 59 }

  condition:
    any of them
}