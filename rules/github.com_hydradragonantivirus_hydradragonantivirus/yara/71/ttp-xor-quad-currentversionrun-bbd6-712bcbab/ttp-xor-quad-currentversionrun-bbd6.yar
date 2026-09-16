rule TTP_XOR_QUAD_CurrentVersionRun_bbd6 {
  strings:
    $key_bbd6 = { e8 b9 [2] cc b7 [2] e7 9b [2] c9 b9 [2] dd a2 [2] d2 b8 [2] cc a5 [2] ce a4 [2] d5 a2 [2] c9 a5 [2] d5 8a }

  condition:
    any of them
}