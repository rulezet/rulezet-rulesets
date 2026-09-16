rule TTP_XOR_QUAD_CurrentVersionRun_fed6 {
  strings:
    $key_fed6 = { ad b9 [2] 89 b7 [2] a2 9b [2] 8c b9 [2] 98 a2 [2] 97 b8 [2] 89 a5 [2] 8b a4 [2] 90 a2 [2] 8c a5 [2] 90 8a }

  condition:
    any of them
}