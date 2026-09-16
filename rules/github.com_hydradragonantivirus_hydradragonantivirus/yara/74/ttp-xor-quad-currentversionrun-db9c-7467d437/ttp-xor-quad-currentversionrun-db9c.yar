rule TTP_XOR_QUAD_CurrentVersionRun_db9c {
  strings:
    $key_db9c = { 88 f3 [2] ac fd [2] 87 d1 [2] a9 f3 [2] bd e8 [2] b2 f2 [2] ac ef [2] ae ee [2] b5 e8 [2] a9 ef [2] b5 c0 }

  condition:
    any of them
}