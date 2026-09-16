rule TTP_XOR_QUAD_CurrentVersionRun_aec4 {
  strings:
    $key_aec4 = { fd ab [2] d9 a5 [2] f2 89 [2] dc ab [2] c8 b0 [2] c7 aa [2] d9 b7 [2] db b6 [2] c0 b0 [2] dc b7 [2] c0 98 }

  condition:
    any of them
}