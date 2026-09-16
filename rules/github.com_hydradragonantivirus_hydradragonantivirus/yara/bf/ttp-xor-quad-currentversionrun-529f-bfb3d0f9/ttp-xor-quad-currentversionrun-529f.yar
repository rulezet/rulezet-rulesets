rule TTP_XOR_QUAD_CurrentVersionRun_529f {
  strings:
    $key_529f = { 01 f0 [2] 25 fe [2] 0e d2 [2] 20 f0 [2] 34 eb [2] 3b f1 [2] 25 ec [2] 27 ed [2] 3c eb [2] 20 ec [2] 3c c3 }

  condition:
    any of them
}