rule TTP_XOR_QUAD_CurrentVersionRun_d8a8 {
  strings:
    $key_d8a8 = { 8b c7 [2] af c9 [2] 84 e5 [2] aa c7 [2] be dc [2] b1 c6 [2] af db [2] ad da [2] b6 dc [2] aa db [2] b6 f4 }

  condition:
    any of them
}