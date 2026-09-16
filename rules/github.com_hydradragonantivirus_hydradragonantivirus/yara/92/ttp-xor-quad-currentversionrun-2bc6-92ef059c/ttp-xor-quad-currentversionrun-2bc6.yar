rule TTP_XOR_QUAD_CurrentVersionRun_2bc6 {
  strings:
    $key_2bc6 = { 78 a9 [2] 5c a7 [2] 77 8b [2] 59 a9 [2] 4d b2 [2] 42 a8 [2] 5c b5 [2] 5e b4 [2] 45 b2 [2] 59 b5 [2] 45 9a }

  condition:
    any of them
}