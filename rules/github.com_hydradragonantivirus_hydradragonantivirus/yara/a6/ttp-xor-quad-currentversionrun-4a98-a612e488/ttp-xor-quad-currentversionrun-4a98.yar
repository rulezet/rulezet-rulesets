rule TTP_XOR_QUAD_CurrentVersionRun_4a98 {
  strings:
    $key_4a98 = { 19 f7 [2] 3d f9 [2] 16 d5 [2] 38 f7 [2] 2c ec [2] 23 f6 [2] 3d eb [2] 3f ea [2] 24 ec [2] 38 eb [2] 24 c4 }

  condition:
    any of them
}