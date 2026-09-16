rule TTP_XOR_QUAD_CurrentVersionRun_6498 {
  strings:
    $key_6498 = { 37 f7 [2] 13 f9 [2] 38 d5 [2] 16 f7 [2] 02 ec [2] 0d f6 [2] 13 eb [2] 11 ea [2] 0a ec [2] 16 eb [2] 0a c4 }

  condition:
    any of them
}