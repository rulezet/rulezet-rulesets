rule TTP_XOR_QUAD_CurrentVersionRun_229f {
  strings:
    $key_229f = { 71 f0 [2] 55 fe [2] 7e d2 [2] 50 f0 [2] 44 eb [2] 4b f1 [2] 55 ec [2] 57 ed [2] 4c eb [2] 50 ec [2] 4c c3 }

  condition:
    any of them
}