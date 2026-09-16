rule TTP_XOR_QUAD_CurrentVersionRun_bfb9 {
  strings:
    $key_bfb9 = { ec d6 [2] c8 d8 [2] e3 f4 [2] cd d6 [2] d9 cd [2] d6 d7 [2] c8 ca [2] ca cb [2] d1 cd [2] cd ca [2] d1 e5 }

  condition:
    any of them
}