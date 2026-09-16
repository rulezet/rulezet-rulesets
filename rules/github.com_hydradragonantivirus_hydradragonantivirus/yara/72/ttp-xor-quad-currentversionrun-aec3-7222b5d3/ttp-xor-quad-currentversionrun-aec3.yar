rule TTP_XOR_QUAD_CurrentVersionRun_aec3 {
  strings:
    $key_aec3 = { fd ac [2] d9 a2 [2] f2 8e [2] dc ac [2] c8 b7 [2] c7 ad [2] d9 b0 [2] db b1 [2] c0 b7 [2] dc b0 [2] c0 9f }

  condition:
    any of them
}