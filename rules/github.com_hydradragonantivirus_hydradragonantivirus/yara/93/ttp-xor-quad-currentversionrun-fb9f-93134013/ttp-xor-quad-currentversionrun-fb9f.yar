rule TTP_XOR_QUAD_CurrentVersionRun_fb9f {
  strings:
    $key_fb9f = { a8 f0 [2] 8c fe [2] a7 d2 [2] 89 f0 [2] 9d eb [2] 92 f1 [2] 8c ec [2] 8e ed [2] 95 eb [2] 89 ec [2] 95 c3 }

  condition:
    any of them
}