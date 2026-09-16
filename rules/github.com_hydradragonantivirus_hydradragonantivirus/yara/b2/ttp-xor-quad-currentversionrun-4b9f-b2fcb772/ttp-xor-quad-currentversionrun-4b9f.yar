rule TTP_XOR_QUAD_CurrentVersionRun_4b9f {
  strings:
    $key_4b9f = { 18 f0 [2] 3c fe [2] 17 d2 [2] 39 f0 [2] 2d eb [2] 22 f1 [2] 3c ec [2] 3e ed [2] 25 eb [2] 39 ec [2] 25 c3 }

  condition:
    any of them
}