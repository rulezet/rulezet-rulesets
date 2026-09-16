rule TTP_XOR_QUAD_CurrentVersionRun_7f9f {
  strings:
    $key_7f9f = { 2c f0 [2] 08 fe [2] 23 d2 [2] 0d f0 [2] 19 eb [2] 16 f1 [2] 08 ec [2] 0a ed [2] 11 eb [2] 0d ec [2] 11 c3 }

  condition:
    any of them
}