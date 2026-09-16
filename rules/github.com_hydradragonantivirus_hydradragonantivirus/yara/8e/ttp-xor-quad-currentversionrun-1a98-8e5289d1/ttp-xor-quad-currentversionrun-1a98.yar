rule TTP_XOR_QUAD_CurrentVersionRun_1a98 {
  strings:
    $key_1a98 = { 49 f7 [2] 6d f9 [2] 46 d5 [2] 68 f7 [2] 7c ec [2] 73 f6 [2] 6d eb [2] 6f ea [2] 74 ec [2] 68 eb [2] 74 c4 }

  condition:
    any of them
}