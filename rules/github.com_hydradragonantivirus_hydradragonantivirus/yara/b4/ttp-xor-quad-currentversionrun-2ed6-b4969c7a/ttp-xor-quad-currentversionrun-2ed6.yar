rule TTP_XOR_QUAD_CurrentVersionRun_2ed6 {
  strings:
    $key_2ed6 = { 7d b9 [2] 59 b7 [2] 72 9b [2] 5c b9 [2] 48 a2 [2] 47 b8 [2] 59 a5 [2] 5b a4 [2] 40 a2 [2] 5c a5 [2] 40 8a }

  condition:
    any of them
}