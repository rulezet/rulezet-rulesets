rule TTP_XOR_QUAD_CurrentVersionRun_4181 {
  strings:
    $key_4181 = { 12 ee [2] 36 e0 [2] 1d cc [2] 33 ee [2] 27 f5 [2] 28 ef [2] 36 f2 [2] 34 f3 [2] 2f f5 [2] 33 f2 [2] 2f dd }

  condition:
    any of them
}