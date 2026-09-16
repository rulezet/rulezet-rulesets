rule TTP_XOR_QUAD_CurrentVersionRun_f69c {
  strings:
    $key_f69c = { a5 f3 [2] 81 fd [2] aa d1 [2] 84 f3 [2] 90 e8 [2] 9f f2 [2] 81 ef [2] 83 ee [2] 98 e8 [2] 84 ef [2] 98 c0 }

  condition:
    any of them
}