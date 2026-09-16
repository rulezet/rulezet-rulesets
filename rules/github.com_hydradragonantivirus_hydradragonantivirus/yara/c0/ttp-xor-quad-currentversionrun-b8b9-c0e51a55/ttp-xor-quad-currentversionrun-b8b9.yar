rule TTP_XOR_QUAD_CurrentVersionRun_b8b9 {
  strings:
    $key_b8b9 = { eb d6 [2] cf d8 [2] e4 f4 [2] ca d6 [2] de cd [2] d1 d7 [2] cf ca [2] cd cb [2] d6 cd [2] ca ca [2] d6 e5 }

  condition:
    any of them
}