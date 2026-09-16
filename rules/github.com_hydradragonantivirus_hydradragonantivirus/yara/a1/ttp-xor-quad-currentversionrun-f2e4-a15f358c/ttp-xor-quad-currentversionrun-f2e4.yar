rule TTP_XOR_QUAD_CurrentVersionRun_f2e4 {
  strings:
    $key_f2e4 = { a1 8b [2] 85 85 [2] ae a9 [2] 80 8b [2] 94 90 [2] 9b 8a [2] 85 97 [2] 87 96 [2] 9c 90 [2] 80 97 [2] 9c b8 }

  condition:
    any of them
}