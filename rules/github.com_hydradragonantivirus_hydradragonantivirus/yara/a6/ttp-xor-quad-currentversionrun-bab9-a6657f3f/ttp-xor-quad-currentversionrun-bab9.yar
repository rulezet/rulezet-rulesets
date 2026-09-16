rule TTP_XOR_QUAD_CurrentVersionRun_bab9 {
  strings:
    $key_bab9 = { e9 d6 [2] cd d8 [2] e6 f4 [2] c8 d6 [2] dc cd [2] d3 d7 [2] cd ca [2] cf cb [2] d4 cd [2] c8 ca [2] d4 e5 }

  condition:
    any of them
}