rule TTP_XOR_QUAD_CurrentVersionRun_abac {
  strings:
    $key_abac = { f8 c3 [2] dc cd [2] f7 e1 [2] d9 c3 [2] cd d8 [2] c2 c2 [2] dc df [2] de de [2] c5 d8 [2] d9 df [2] c5 f0 }

  condition:
    any of them
}