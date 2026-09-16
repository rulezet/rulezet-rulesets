rule TTP_XOR_QUAD_CurrentVersionRun_279c {
  strings:
    $key_279c = { 74 f3 [2] 50 fd [2] 7b d1 [2] 55 f3 [2] 41 e8 [2] 4e f2 [2] 50 ef [2] 52 ee [2] 49 e8 [2] 55 ef [2] 49 c0 }

  condition:
    any of them
}