rule TTP_XOR_QUAD_CurrentVersionRun_a082 {
  strings:
    $key_a082 = { f3 ed [2] d7 e3 [2] fc cf [2] d2 ed [2] c6 f6 [2] c9 ec [2] d7 f1 [2] d5 f0 [2] ce f6 [2] d2 f1 [2] ce de }

  condition:
    any of them
}