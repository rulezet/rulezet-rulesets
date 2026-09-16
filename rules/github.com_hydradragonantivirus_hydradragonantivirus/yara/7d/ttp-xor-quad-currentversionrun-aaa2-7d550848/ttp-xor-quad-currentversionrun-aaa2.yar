rule TTP_XOR_QUAD_CurrentVersionRun_aaa2 {
  strings:
    $key_aaa2 = { f9 cd [2] dd c3 [2] f6 ef [2] d8 cd [2] cc d6 [2] c3 cc [2] dd d1 [2] df d0 [2] c4 d6 [2] d8 d1 [2] c4 fe }

  condition:
    any of them
}