rule TTP_XOR_QUAD_CurrentVersionRun_eb9c {
  strings:
    $key_eb9c = { b8 f3 [2] 9c fd [2] b7 d1 [2] 99 f3 [2] 8d e8 [2] 82 f2 [2] 9c ef [2] 9e ee [2] 85 e8 [2] 99 ef [2] 85 c0 }

  condition:
    any of them
}