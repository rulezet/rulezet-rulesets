rule TTP_XOR_QUAD_CurrentVersionRun_769c {
  strings:
    $key_769c = { 25 f3 [2] 01 fd [2] 2a d1 [2] 04 f3 [2] 10 e8 [2] 1f f2 [2] 01 ef [2] 03 ee [2] 18 e8 [2] 04 ef [2] 18 c0 }

  condition:
    any of them
}