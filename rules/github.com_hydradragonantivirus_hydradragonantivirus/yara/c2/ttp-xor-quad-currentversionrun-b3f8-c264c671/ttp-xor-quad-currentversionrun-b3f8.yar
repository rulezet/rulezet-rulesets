rule TTP_XOR_QUAD_CurrentVersionRun_b3f8 {
  strings:
    $key_b3f8 = { e0 97 [2] c4 99 [2] ef b5 [2] c1 97 [2] d5 8c [2] da 96 [2] c4 8b [2] c6 8a [2] dd 8c [2] c1 8b [2] dd a4 }

  condition:
    any of them
}