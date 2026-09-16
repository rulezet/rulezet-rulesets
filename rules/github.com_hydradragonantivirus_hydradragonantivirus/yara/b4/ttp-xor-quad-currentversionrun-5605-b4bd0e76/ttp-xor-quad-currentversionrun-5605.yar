rule TTP_XOR_QUAD_CurrentVersionRun_5605 {
  strings:
    $key_5605 = { 05 6a [2] 21 64 [2] 0a 48 [2] 24 6a [2] 30 71 [2] 3f 6b [2] 21 76 [2] 23 77 [2] 38 71 [2] 24 76 [2] 38 59 }

  condition:
    any of them
}