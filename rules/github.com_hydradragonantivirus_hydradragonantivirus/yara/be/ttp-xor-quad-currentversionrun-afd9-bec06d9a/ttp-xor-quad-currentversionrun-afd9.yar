rule TTP_XOR_QUAD_CurrentVersionRun_afd9 {
  strings:
    $key_afd9 = { fc b6 [2] d8 b8 [2] f3 94 [2] dd b6 [2] c9 ad [2] c6 b7 [2] d8 aa [2] da ab [2] c1 ad [2] dd aa [2] c1 85 }

  condition:
    any of them
}