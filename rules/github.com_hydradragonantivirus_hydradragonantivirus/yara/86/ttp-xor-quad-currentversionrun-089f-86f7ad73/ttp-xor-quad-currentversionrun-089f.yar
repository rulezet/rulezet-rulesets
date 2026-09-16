rule TTP_XOR_QUAD_CurrentVersionRun_089f {
  strings:
    $key_089f = { 5b f0 [2] 7f fe [2] 54 d2 [2] 7a f0 [2] 6e eb [2] 61 f1 [2] 7f ec [2] 7d ed [2] 66 eb [2] 7a ec [2] 66 c3 }

  condition:
    any of them
}