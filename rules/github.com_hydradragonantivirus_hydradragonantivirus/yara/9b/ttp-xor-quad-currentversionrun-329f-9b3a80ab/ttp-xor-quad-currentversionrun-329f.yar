rule TTP_XOR_QUAD_CurrentVersionRun_329f {
  strings:
    $key_329f = { 61 f0 [2] 45 fe [2] 6e d2 [2] 40 f0 [2] 54 eb [2] 5b f1 [2] 45 ec [2] 47 ed [2] 5c eb [2] 40 ec [2] 5c c3 }

  condition:
    any of them
}