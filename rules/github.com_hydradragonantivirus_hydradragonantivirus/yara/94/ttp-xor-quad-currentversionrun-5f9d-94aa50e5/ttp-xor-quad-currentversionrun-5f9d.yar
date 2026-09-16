rule TTP_XOR_QUAD_CurrentVersionRun_5f9d {
  strings:
    $key_5f9d = { 0c f2 [2] 28 fc [2] 03 d0 [2] 2d f2 [2] 39 e9 [2] 36 f3 [2] 28 ee [2] 2a ef [2] 31 e9 [2] 2d ee [2] 31 c1 }

  condition:
    any of them
}