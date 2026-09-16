rule TTP_XOR_QUAD_CurrentVersionRun_acd6 {
  strings:
    $key_acd6 = { ff b9 [2] db b7 [2] f0 9b [2] de b9 [2] ca a2 [2] c5 b8 [2] db a5 [2] d9 a4 [2] c2 a2 [2] de a5 [2] c2 8a }

  condition:
    any of them
}