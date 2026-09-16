rule TTP_XOR_QUAD_CurrentVersionRun_12c6 {
  strings:
    $key_12c6 = { 41 a9 [2] 65 a7 [2] 4e 8b [2] 60 a9 [2] 74 b2 [2] 7b a8 [2] 65 b5 [2] 67 b4 [2] 7c b2 [2] 60 b5 [2] 7c 9a }

  condition:
    any of them
}