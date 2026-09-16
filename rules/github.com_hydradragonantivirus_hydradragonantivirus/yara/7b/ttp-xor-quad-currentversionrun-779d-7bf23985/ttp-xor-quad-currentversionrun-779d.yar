rule TTP_XOR_QUAD_CurrentVersionRun_779d {
  strings:
    $key_779d = { 24 f2 [2] 00 fc [2] 2b d0 [2] 05 f2 [2] 11 e9 [2] 1e f3 [2] 00 ee [2] 02 ef [2] 19 e9 [2] 05 ee [2] 19 c1 }

  condition:
    any of them
}