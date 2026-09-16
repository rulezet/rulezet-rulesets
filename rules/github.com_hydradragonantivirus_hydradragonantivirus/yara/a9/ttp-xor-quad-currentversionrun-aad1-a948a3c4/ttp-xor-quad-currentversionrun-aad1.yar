rule TTP_XOR_QUAD_CurrentVersionRun_aad1 {
  strings:
    $key_aad1 = { f9 be [2] dd b0 [2] f6 9c [2] d8 be [2] cc a5 [2] c3 bf [2] dd a2 [2] df a3 [2] c4 a5 [2] d8 a2 [2] c4 8d }

  condition:
    any of them
}