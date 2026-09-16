rule TTP_XOR_QUAD_CurrentVersionRun_6a9c {
  strings:
    $key_6a9c = { 39 f3 [2] 1d fd [2] 36 d1 [2] 18 f3 [2] 0c e8 [2] 03 f2 [2] 1d ef [2] 1f ee [2] 04 e8 [2] 18 ef [2] 04 c0 }

  condition:
    any of them
}