rule TTP_XOR_QUAD_CurrentVersionRun_21e4 {
  strings:
    $key_21e4 = { 72 8b [2] 56 85 [2] 7d a9 [2] 53 8b [2] 47 90 [2] 48 8a [2] 56 97 [2] 54 96 [2] 4f 90 [2] 53 97 [2] 4f b8 }

  condition:
    any of them
}