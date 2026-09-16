rule TTP_XOR_QUAD_CurrentVersionRun_049c {
  strings:
    $key_049c = { 57 f3 [2] 73 fd [2] 58 d1 [2] 76 f3 [2] 62 e8 [2] 6d f2 [2] 73 ef [2] 71 ee [2] 6a e8 [2] 76 ef [2] 6a c0 }

  condition:
    any of them
}