rule TTP_XOR_QUAD_CurrentVersionRun_aab4 {
  strings:
    $key_aab4 = { f9 db [2] dd d5 [2] f6 f9 [2] d8 db [2] cc c0 [2] c3 da [2] dd c7 [2] df c6 [2] c4 c0 [2] d8 c7 [2] c4 e8 }

  condition:
    any of them
}