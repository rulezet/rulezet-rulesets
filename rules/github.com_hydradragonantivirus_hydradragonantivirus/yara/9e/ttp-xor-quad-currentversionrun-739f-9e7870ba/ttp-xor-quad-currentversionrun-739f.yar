rule TTP_XOR_QUAD_CurrentVersionRun_739f {
  strings:
    $key_739f = { 20 f0 [2] 04 fe [2] 2f d2 [2] 01 f0 [2] 15 eb [2] 1a f1 [2] 04 ec [2] 06 ed [2] 1d eb [2] 01 ec [2] 1d c3 }

  condition:
    any of them
}