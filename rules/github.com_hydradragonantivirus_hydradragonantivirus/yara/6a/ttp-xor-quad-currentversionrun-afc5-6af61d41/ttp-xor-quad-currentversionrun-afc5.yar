rule TTP_XOR_QUAD_CurrentVersionRun_afc5 {
  strings:
    $key_afc5 = { fc aa [2] d8 a4 [2] f3 88 [2] dd aa [2] c9 b1 [2] c6 ab [2] d8 b6 [2] da b7 [2] c1 b1 [2] dd b6 [2] c1 99 }

  condition:
    any of them
}