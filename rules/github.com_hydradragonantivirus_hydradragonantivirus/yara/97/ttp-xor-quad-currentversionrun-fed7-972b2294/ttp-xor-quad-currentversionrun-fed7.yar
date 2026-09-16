rule TTP_XOR_QUAD_CurrentVersionRun_fed7 {
  strings:
    $key_fed7 = { ad b8 [2] 89 b6 [2] a2 9a [2] 8c b8 [2] 98 a3 [2] 97 b9 [2] 89 a4 [2] 8b a5 [2] 90 a3 [2] 8c a4 [2] 90 8b }

  condition:
    any of them
}