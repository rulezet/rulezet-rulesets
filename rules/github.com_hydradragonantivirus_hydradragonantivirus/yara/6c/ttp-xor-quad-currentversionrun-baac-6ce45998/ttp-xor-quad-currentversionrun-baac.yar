rule TTP_XOR_QUAD_CurrentVersionRun_baac {
  strings:
    $key_baac = { e9 c3 [2] cd cd [2] e6 e1 [2] c8 c3 [2] dc d8 [2] d3 c2 [2] cd df [2] cf de [2] d4 d8 [2] c8 df [2] d4 f0 }

  condition:
    any of them
}