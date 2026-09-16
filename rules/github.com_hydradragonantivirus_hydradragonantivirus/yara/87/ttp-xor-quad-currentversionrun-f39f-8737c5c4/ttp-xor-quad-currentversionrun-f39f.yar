rule TTP_XOR_QUAD_CurrentVersionRun_f39f {
  strings:
    $key_f39f = { a0 f0 [2] 84 fe [2] af d2 [2] 81 f0 [2] 95 eb [2] 9a f1 [2] 84 ec [2] 86 ed [2] 9d eb [2] 81 ec [2] 9d c3 }

  condition:
    any of them
}