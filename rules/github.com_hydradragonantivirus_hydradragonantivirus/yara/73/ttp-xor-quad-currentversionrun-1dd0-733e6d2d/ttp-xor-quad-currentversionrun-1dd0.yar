rule TTP_XOR_QUAD_CurrentVersionRun_1dd0 {
  strings:
    $key_1dd0 = { 4e bf [2] 6a b1 [2] 41 9d [2] 6f bf [2] 7b a4 [2] 74 be [2] 6a a3 [2] 68 a2 [2] 73 a4 [2] 6f a3 [2] 73 8c }

  condition:
    any of them
}