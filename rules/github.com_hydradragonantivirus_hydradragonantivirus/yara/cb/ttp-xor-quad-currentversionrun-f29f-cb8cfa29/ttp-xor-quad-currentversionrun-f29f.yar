rule TTP_XOR_QUAD_CurrentVersionRun_f29f {
  strings:
    $key_f29f = { a1 f0 [2] 85 fe [2] ae d2 [2] 80 f0 [2] 94 eb [2] 9b f1 [2] 85 ec [2] 87 ed [2] 9c eb [2] 80 ec [2] 9c c3 }

  condition:
    any of them
}