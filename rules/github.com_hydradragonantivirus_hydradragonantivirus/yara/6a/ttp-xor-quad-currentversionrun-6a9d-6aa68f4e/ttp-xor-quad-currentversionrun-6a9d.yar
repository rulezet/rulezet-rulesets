rule TTP_XOR_QUAD_CurrentVersionRun_6a9d {
  strings:
    $key_6a9d = { 39 f2 [2] 1d fc [2] 36 d0 [2] 18 f2 [2] 0c e9 [2] 03 f3 [2] 1d ee [2] 1f ef [2] 04 e9 [2] 18 ee [2] 04 c1 }

  condition:
    any of them
}