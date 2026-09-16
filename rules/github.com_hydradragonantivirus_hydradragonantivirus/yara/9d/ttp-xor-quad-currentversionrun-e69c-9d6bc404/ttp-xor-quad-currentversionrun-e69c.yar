rule TTP_XOR_QUAD_CurrentVersionRun_e69c {
  strings:
    $key_e69c = { b5 f3 [2] 91 fd [2] ba d1 [2] 94 f3 [2] 80 e8 [2] 8f f2 [2] 91 ef [2] 93 ee [2] 88 e8 [2] 94 ef [2] 88 c0 }

  condition:
    any of them
}