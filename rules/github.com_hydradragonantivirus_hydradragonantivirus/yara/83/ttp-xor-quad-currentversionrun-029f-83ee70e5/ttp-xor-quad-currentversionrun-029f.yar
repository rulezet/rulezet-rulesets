rule TTP_XOR_QUAD_CurrentVersionRun_029f {
  strings:
    $key_029f = { 51 f0 [2] 75 fe [2] 5e d2 [2] 70 f0 [2] 64 eb [2] 6b f1 [2] 75 ec [2] 77 ed [2] 6c eb [2] 70 ec [2] 6c c3 }

  condition:
    any of them
}