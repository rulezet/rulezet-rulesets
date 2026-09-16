rule TTP_XOR_QUAD_CurrentVersionRun_709c {
  strings:
    $key_709c = { 23 f3 [2] 07 fd [2] 2c d1 [2] 02 f3 [2] 16 e8 [2] 19 f2 [2] 07 ef [2] 05 ee [2] 1e e8 [2] 02 ef [2] 1e c0 }

  condition:
    any of them
}