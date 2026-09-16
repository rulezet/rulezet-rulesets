rule TTP_XOR_QUAD_CurrentVersionRun_589f {
  strings:
    $key_589f = { 0b f0 [2] 2f fe [2] 04 d2 [2] 2a f0 [2] 3e eb [2] 31 f1 [2] 2f ec [2] 2d ed [2] 36 eb [2] 2a ec [2] 36 c3 }

  condition:
    any of them
}