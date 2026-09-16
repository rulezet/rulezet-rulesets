rule TTP_XOR_QUAD_CurrentVersionRun_7f9d {
  strings:
    $key_7f9d = { 2c f2 [2] 08 fc [2] 23 d0 [2] 0d f2 [2] 19 e9 [2] 16 f3 [2] 08 ee [2] 0a ef [2] 11 e9 [2] 0d ee [2] 11 c1 }

  condition:
    any of them
}