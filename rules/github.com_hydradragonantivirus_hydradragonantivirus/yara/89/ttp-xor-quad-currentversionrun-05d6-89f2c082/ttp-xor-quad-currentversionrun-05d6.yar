rule TTP_XOR_QUAD_CurrentVersionRun_05d6 {
  strings:
    $key_05d6 = { 56 b9 [2] 72 b7 [2] 59 9b [2] 77 b9 [2] 63 a2 [2] 6c b8 [2] 72 a5 [2] 70 a4 [2] 6b a2 [2] 77 a5 [2] 6b 8a }

  condition:
    any of them
}