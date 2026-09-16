rule TTP_XOR_QUAD_CurrentVersionRun_aaa8 {
  strings:
    $key_aaa8 = { f9 c7 [2] dd c9 [2] f6 e5 [2] d8 c7 [2] cc dc [2] c3 c6 [2] dd db [2] df da [2] c4 dc [2] d8 db [2] c4 f4 }

  condition:
    any of them
}