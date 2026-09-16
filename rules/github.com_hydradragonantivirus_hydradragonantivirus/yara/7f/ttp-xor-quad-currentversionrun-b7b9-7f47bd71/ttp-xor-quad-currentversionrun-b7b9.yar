rule TTP_XOR_QUAD_CurrentVersionRun_b7b9 {
  strings:
    $key_b7b9 = { e4 d6 [2] c0 d8 [2] eb f4 [2] c5 d6 [2] d1 cd [2] de d7 [2] c0 ca [2] c2 cb [2] d9 cd [2] c5 ca [2] d9 e5 }

  condition:
    any of them
}