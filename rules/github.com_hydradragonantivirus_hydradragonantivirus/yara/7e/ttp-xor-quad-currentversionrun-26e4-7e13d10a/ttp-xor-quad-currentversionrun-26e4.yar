rule TTP_XOR_QUAD_CurrentVersionRun_26e4 {
  strings:
    $key_26e4 = { 75 8b [2] 51 85 [2] 7a a9 [2] 54 8b [2] 40 90 [2] 4f 8a [2] 51 97 [2] 53 96 [2] 48 90 [2] 54 97 [2] 48 b8 }

  condition:
    any of them
}