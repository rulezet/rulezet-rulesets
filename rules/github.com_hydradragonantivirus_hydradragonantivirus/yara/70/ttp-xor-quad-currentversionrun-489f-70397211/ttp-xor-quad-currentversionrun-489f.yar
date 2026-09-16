rule TTP_XOR_QUAD_CurrentVersionRun_489f {
  strings:
    $key_489f = { 1b f0 [2] 3f fe [2] 14 d2 [2] 3a f0 [2] 2e eb [2] 21 f1 [2] 3f ec [2] 3d ed [2] 26 eb [2] 3a ec [2] 26 c3 }

  condition:
    any of them
}