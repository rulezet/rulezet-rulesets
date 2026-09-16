rule TTP_XOR_QUAD_CurrentVersionRun_afd7 {
  strings:
    $key_afd7 = { fc b8 [2] d8 b6 [2] f3 9a [2] dd b8 [2] c9 a3 [2] c6 b9 [2] d8 a4 [2] da a5 [2] c1 a3 [2] dd a4 [2] c1 8b }

  condition:
    any of them
}