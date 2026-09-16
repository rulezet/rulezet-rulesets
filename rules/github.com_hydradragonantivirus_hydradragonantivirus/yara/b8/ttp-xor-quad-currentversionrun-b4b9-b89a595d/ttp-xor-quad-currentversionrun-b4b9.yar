rule TTP_XOR_QUAD_CurrentVersionRun_b4b9 {
  strings:
    $key_b4b9 = { e7 d6 [2] c3 d8 [2] e8 f4 [2] c6 d6 [2] d2 cd [2] dd d7 [2] c3 ca [2] c1 cb [2] da cd [2] c6 ca [2] da e5 }

  condition:
    any of them
}