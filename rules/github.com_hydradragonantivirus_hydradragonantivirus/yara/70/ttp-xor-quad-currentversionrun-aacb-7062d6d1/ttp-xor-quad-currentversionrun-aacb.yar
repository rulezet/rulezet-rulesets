rule TTP_XOR_QUAD_CurrentVersionRun_aacb {
  strings:
    $key_aacb = { f9 a4 [2] dd aa [2] f6 86 [2] d8 a4 [2] cc bf [2] c3 a5 [2] dd b8 [2] df b9 [2] c4 bf [2] d8 b8 [2] c4 97 }

  condition:
    any of them
}