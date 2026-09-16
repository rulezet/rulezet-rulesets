rule TTP_XOR_QUAD_CurrentVersionRun_a782 {
  strings:
    $key_a782 = { f4 ed [2] d0 e3 [2] fb cf [2] d5 ed [2] c1 f6 [2] ce ec [2] d0 f1 [2] d2 f0 [2] c9 f6 [2] d5 f1 [2] c9 de }

  condition:
    any of them
}