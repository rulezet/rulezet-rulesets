rule TTP_XOR_QUAD_CurrentVersionRun_ac98 {
  strings:
    $key_ac98 = { ff f7 [2] db f9 [2] f0 d5 [2] de f7 [2] ca ec [2] c5 f6 [2] db eb [2] d9 ea [2] c2 ec [2] de eb [2] c2 c4 }

  condition:
    any of them
}