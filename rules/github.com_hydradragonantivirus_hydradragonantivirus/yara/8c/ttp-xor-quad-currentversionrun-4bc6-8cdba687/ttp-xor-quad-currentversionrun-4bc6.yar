rule TTP_XOR_QUAD_CurrentVersionRun_4bc6 {
  strings:
    $key_4bc6 = { 18 a9 [2] 3c a7 [2] 17 8b [2] 39 a9 [2] 2d b2 [2] 22 a8 [2] 3c b5 [2] 3e b4 [2] 25 b2 [2] 39 b5 [2] 25 9a }

  condition:
    any of them
}