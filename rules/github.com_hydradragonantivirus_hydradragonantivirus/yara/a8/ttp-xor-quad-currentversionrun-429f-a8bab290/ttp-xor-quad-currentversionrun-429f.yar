rule TTP_XOR_QUAD_CurrentVersionRun_429f {
  strings:
    $key_429f = { 11 f0 [2] 35 fe [2] 1e d2 [2] 30 f0 [2] 24 eb [2] 2b f1 [2] 35 ec [2] 37 ed [2] 2c eb [2] 30 ec [2] 2c c3 }

  condition:
    any of them
}