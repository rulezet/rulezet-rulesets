rule TTP_XOR_QUAD_CurrentVersionRun_aad9 {
  strings:
    $key_aad9 = { f9 b6 [2] dd b8 [2] f6 94 [2] d8 b6 [2] cc ad [2] c3 b7 [2] dd aa [2] df ab [2] c4 ad [2] d8 aa [2] c4 85 }

  condition:
    any of them
}