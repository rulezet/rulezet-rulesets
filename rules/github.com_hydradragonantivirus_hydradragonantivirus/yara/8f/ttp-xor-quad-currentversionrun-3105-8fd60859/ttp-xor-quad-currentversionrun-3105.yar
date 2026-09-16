rule TTP_XOR_QUAD_CurrentVersionRun_3105 {
  strings:
    $key_3105 = { 62 6a [2] 46 64 [2] 6d 48 [2] 43 6a [2] 57 71 [2] 58 6b [2] 46 76 [2] 44 77 [2] 5f 71 [2] 43 76 [2] 5f 59 }

  condition:
    any of them
}