rule TTP_XOR_QUAD_CurrentVersionRun_aec7 {
  strings:
    $key_aec7 = { fd a8 [2] d9 a6 [2] f2 8a [2] dc a8 [2] c8 b3 [2] c7 a9 [2] d9 b4 [2] db b5 [2] c0 b3 [2] dc b4 [2] c0 9b }

  condition:
    any of them
}