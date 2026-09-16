rule TTP_XOR_QUAD_CurrentVersionRun_11e4 {
  strings:
    $key_11e4 = { 42 8b [2] 66 85 [2] 4d a9 [2] 63 8b [2] 77 90 [2] 78 8a [2] 66 97 [2] 64 96 [2] 7f 90 [2] 63 97 [2] 7f b8 }

  condition:
    any of them
}