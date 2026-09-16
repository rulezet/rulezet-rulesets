rule TTP_XOR_QUAD_CurrentVersionRun_e39f {
  strings:
    $key_e39f = { b0 f0 [2] 94 fe [2] bf d2 [2] 91 f0 [2] 85 eb [2] 8a f1 [2] 94 ec [2] 96 ed [2] 8d eb [2] 91 ec [2] 8d c3 }

  condition:
    any of them
}