rule TTP_XOR_QUAD_CurrentVersionRun_fbc7 {
  strings:
    $key_fbc7 = { a8 a8 [2] 8c a6 [2] a7 8a [2] 89 a8 [2] 9d b3 [2] 92 a9 [2] 8c b4 [2] 8e b5 [2] 95 b3 [2] 89 b4 [2] 95 9b }

  condition:
    any of them
}