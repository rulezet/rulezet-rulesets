rule TTP_XOR_QUAD_CurrentVersionRun_a9ca {
  strings:
    $key_a9ca = { fa a5 [2] de ab [2] f5 87 [2] db a5 [2] cf be [2] c0 a4 [2] de b9 [2] dc b8 [2] c7 be [2] db b9 [2] c7 96 }

  condition:
    any of them
}