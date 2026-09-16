rule TTP_XOR_QUAD_CurrentVersionRun_baab {
  strings:
    $key_baab = { e9 c4 [2] cd ca [2] e6 e6 [2] c8 c4 [2] dc df [2] d3 c5 [2] cd d8 [2] cf d9 [2] d4 df [2] c8 d8 [2] d4 f7 }

  condition:
    any of them
}