rule TTP_XOR_QUAD_CurrentVersionRun_2b9c {
  strings:
    $key_2b9c = { 78 f3 [2] 5c fd [2] 77 d1 [2] 59 f3 [2] 4d e8 [2] 42 f2 [2] 5c ef [2] 5e ee [2] 45 e8 [2] 59 ef [2] 45 c0 }

  condition:
    any of them
}