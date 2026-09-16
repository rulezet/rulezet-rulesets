rule TTP_XOR_QUAD_CurrentVersionRun_05e4 {
  strings:
    $key_05e4 = { 56 8b [2] 72 85 [2] 59 a9 [2] 77 8b [2] 63 90 [2] 6c 8a [2] 72 97 [2] 70 96 [2] 6b 90 [2] 77 97 [2] 6b b8 }

  condition:
    any of them
}