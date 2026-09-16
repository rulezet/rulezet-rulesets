rule TTP_XOR_QUAD_CurrentVersionRun_51e4 {
  strings:
    $key_51e4 = { 02 8b [2] 26 85 [2] 0d a9 [2] 23 8b [2] 37 90 [2] 38 8a [2] 26 97 [2] 24 96 [2] 3f 90 [2] 23 97 [2] 3f b8 }

  condition:
    any of them
}