rule TTP_XOR_QUAD_CurrentVersionRun_b4b6 {
  strings:
    $key_b4b6 = { e7 d9 [2] c3 d7 [2] e8 fb [2] c6 d9 [2] d2 c2 [2] dd d8 [2] c3 c5 [2] c1 c4 [2] da c2 [2] c6 c5 [2] da ea }

  condition:
    any of them
}