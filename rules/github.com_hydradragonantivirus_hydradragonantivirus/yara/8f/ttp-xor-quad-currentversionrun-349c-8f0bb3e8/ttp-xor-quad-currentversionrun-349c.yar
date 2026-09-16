rule TTP_XOR_QUAD_CurrentVersionRun_349c {
  strings:
    $key_349c = { 67 f3 [2] 43 fd [2] 68 d1 [2] 46 f3 [2] 52 e8 [2] 5d f2 [2] 43 ef [2] 41 ee [2] 5a e8 [2] 46 ef [2] 5a c0 }

  condition:
    any of them
}