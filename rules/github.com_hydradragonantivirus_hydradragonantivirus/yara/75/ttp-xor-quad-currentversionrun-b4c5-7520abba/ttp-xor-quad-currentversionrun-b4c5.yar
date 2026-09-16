rule TTP_XOR_QUAD_CurrentVersionRun_b4c5 {
  strings:
    $key_b4c5 = { e7 aa [2] c3 a4 [2] e8 88 [2] c6 aa [2] d2 b1 [2] dd ab [2] c3 b6 [2] c1 b7 [2] da b1 [2] c6 b6 [2] da 99 }

  condition:
    any of them
}