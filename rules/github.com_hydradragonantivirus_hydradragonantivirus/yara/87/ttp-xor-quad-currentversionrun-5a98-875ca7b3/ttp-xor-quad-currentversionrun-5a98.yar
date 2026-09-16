rule TTP_XOR_QUAD_CurrentVersionRun_5a98 {
  strings:
    $key_5a98 = { 09 f7 [2] 2d f9 [2] 06 d5 [2] 28 f7 [2] 3c ec [2] 33 f6 [2] 2d eb [2] 2f ea [2] 34 ec [2] 28 eb [2] 34 c4 }

  condition:
    any of them
}