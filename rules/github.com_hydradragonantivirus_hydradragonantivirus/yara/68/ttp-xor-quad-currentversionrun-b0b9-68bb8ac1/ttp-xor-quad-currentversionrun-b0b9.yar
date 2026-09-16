rule TTP_XOR_QUAD_CurrentVersionRun_b0b9 {
  strings:
    $key_b0b9 = { e3 d6 [2] c7 d8 [2] ec f4 [2] c2 d6 [2] d6 cd [2] d9 d7 [2] c7 ca [2] c5 cb [2] de cd [2] c2 ca [2] de e5 }

  condition:
    any of them
}