rule TTP_XOR_QUAD_CurrentVersionRun_f89f {
  strings:
    $key_f89f = { ab f0 [2] 8f fe [2] a4 d2 [2] 8a f0 [2] 9e eb [2] 91 f1 [2] 8f ec [2] 8d ed [2] 96 eb [2] 8a ec [2] 96 c3 }

  condition:
    any of them
}