rule TTP_XOR_QUAD_CurrentVersionRun_fec7 {
  strings:
    $key_fec7 = { ad a8 [2] 89 a6 [2] a2 8a [2] 8c a8 [2] 98 b3 [2] 97 a9 [2] 89 b4 [2] 8b b5 [2] 90 b3 [2] 8c b4 [2] 90 9b }

  condition:
    any of them
}