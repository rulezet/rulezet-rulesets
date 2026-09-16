rule TTP_XOR_QUAD_CurrentVersionRun_0b9f {
  strings:
    $key_0b9f = { 58 f0 [2] 7c fe [2] 57 d2 [2] 79 f0 [2] 6d eb [2] 62 f1 [2] 7c ec [2] 7e ed [2] 65 eb [2] 79 ec [2] 65 c3 }

  condition:
    any of them
}