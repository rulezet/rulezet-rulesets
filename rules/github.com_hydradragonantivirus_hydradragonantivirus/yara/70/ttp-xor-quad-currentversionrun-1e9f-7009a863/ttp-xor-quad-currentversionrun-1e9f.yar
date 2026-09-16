rule TTP_XOR_QUAD_CurrentVersionRun_1e9f {
  strings:
    $key_1e9f = { 4d f0 [2] 69 fe [2] 42 d2 [2] 6c f0 [2] 78 eb [2] 77 f1 [2] 69 ec [2] 6b ed [2] 70 eb [2] 6c ec [2] 70 c3 }

  condition:
    any of them
}