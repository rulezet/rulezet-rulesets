rule TTP_XOR_QUAD_CurrentVersionRun_aab1 {
  strings:
    $key_aab1 = { f9 de [2] dd d0 [2] f6 fc [2] d8 de [2] cc c5 [2] c3 df [2] dd c2 [2] df c3 [2] c4 c5 [2] d8 c2 [2] c4 ed }

  condition:
    any of them
}