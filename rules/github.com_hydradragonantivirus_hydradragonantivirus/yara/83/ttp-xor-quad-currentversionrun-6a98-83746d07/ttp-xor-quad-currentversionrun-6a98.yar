rule TTP_XOR_QUAD_CurrentVersionRun_6a98 {
  strings:
    $key_6a98 = { 39 f7 [2] 1d f9 [2] 36 d5 [2] 18 f7 [2] 0c ec [2] 03 f6 [2] 1d eb [2] 1f ea [2] 04 ec [2] 18 eb [2] 04 c4 }

  condition:
    any of them
}