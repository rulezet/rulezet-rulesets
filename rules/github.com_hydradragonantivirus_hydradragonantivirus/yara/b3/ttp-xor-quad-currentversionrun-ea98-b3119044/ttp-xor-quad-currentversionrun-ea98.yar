rule TTP_XOR_QUAD_CurrentVersionRun_ea98 {
  strings:
    $key_ea98 = { b9 f7 [2] 9d f9 [2] b6 d5 [2] 98 f7 [2] 8c ec [2] 83 f6 [2] 9d eb [2] 9f ea [2] 84 ec [2] 98 eb [2] 84 c4 }

  condition:
    any of them
}