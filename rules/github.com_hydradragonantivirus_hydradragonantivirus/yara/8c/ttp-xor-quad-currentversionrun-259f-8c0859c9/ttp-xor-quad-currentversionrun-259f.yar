rule TTP_XOR_QUAD_CurrentVersionRun_259f {
  strings:
    $key_259f = { 76 f0 [2] 52 fe [2] 79 d2 [2] 57 f0 [2] 43 eb [2] 4c f1 [2] 52 ec [2] 50 ed [2] 4b eb [2] 57 ec [2] 4b c3 }

  condition:
    any of them
}