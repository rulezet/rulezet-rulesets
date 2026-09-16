rule TTP_XOR_QUAD_CurrentVersionRun_a1aa {
  strings:
    $key_a1aa = { f2 c5 [2] d6 cb [2] fd e7 [2] d3 c5 [2] c7 de [2] c8 c4 [2] d6 d9 [2] d4 d8 [2] cf de [2] d3 d9 [2] cf f6 }

  condition:
    any of them
}