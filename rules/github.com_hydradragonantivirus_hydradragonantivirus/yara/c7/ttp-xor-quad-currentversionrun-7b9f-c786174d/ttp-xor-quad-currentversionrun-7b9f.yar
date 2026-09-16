rule TTP_XOR_QUAD_CurrentVersionRun_7b9f {
  strings:
    $key_7b9f = { 28 f0 [2] 0c fe [2] 27 d2 [2] 09 f0 [2] 1d eb [2] 12 f1 [2] 0c ec [2] 0e ed [2] 15 eb [2] 09 ec [2] 15 c3 }

  condition:
    any of them
}