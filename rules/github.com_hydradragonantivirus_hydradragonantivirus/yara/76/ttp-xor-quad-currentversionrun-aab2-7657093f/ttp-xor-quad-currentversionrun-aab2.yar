rule TTP_XOR_QUAD_CurrentVersionRun_aab2 {
  strings:
    $key_aab2 = { f9 dd [2] dd d3 [2] f6 ff [2] d8 dd [2] cc c6 [2] c3 dc [2] dd c1 [2] df c0 [2] c4 c6 [2] d8 c1 [2] c4 ee }

  condition:
    any of them
}