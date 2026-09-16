rule TTP_XOR_QUAD_CurrentVersionRun_aec5 {
  strings:
    $key_aec5 = { fd aa [2] d9 a4 [2] f2 88 [2] dc aa [2] c8 b1 [2] c7 ab [2] d9 b6 [2] db b7 [2] c0 b1 [2] dc b6 [2] c0 99 }

  condition:
    any of them
}