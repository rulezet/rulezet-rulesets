rule TTP_XOR_QUAD_CurrentVersionRun_3a98 {
  strings:
    $key_3a98 = { 69 f7 [2] 4d f9 [2] 66 d5 [2] 48 f7 [2] 5c ec [2] 53 f6 [2] 4d eb [2] 4f ea [2] 54 ec [2] 48 eb [2] 54 c4 }

  condition:
    any of them
}