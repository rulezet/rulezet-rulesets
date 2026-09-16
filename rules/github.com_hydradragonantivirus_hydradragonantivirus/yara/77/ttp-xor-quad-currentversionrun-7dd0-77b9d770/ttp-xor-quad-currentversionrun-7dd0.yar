rule TTP_XOR_QUAD_CurrentVersionRun_7dd0 {
  strings:
    $key_7dd0 = { 2e bf [2] 0a b1 [2] 21 9d [2] 0f bf [2] 1b a4 [2] 14 be [2] 0a a3 [2] 08 a2 [2] 13 a4 [2] 0f a3 [2] 13 8c }

  condition:
    any of them
}