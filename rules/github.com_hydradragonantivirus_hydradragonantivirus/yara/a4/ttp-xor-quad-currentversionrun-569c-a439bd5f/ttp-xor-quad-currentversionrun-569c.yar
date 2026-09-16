rule TTP_XOR_QUAD_CurrentVersionRun_569c {
  strings:
    $key_569c = { 05 f3 [2] 21 fd [2] 0a d1 [2] 24 f3 [2] 30 e8 [2] 3f f2 [2] 21 ef [2] 23 ee [2] 38 e8 [2] 24 ef [2] 38 c0 }

  condition:
    any of them
}