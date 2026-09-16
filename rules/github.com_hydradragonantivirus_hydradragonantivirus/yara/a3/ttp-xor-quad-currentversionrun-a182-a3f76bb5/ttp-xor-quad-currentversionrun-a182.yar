rule TTP_XOR_QUAD_CurrentVersionRun_a182 {
  strings:
    $key_a182 = { f2 ed [2] d6 e3 [2] fd cf [2] d3 ed [2] c7 f6 [2] c8 ec [2] d6 f1 [2] d4 f0 [2] cf f6 [2] d3 f1 [2] cf de }

  condition:
    any of them
}