rule TTP_XOR_QUAD_CurrentVersionRun_459f {
  strings:
    $key_459f = { 16 f0 [2] 32 fe [2] 19 d2 [2] 37 f0 [2] 23 eb [2] 2c f1 [2] 32 ec [2] 30 ed [2] 2b eb [2] 37 ec [2] 2b c3 }

  condition:
    any of them
}