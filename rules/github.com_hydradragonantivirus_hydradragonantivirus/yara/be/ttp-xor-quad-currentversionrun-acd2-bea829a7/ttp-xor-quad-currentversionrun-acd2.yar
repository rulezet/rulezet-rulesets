rule TTP_XOR_QUAD_CurrentVersionRun_acd2 {
  strings:
    $key_acd2 = { ff bd [2] db b3 [2] f0 9f [2] de bd [2] ca a6 [2] c5 bc [2] db a1 [2] d9 a0 [2] c2 a6 [2] de a1 [2] c2 8e }

  condition:
    any of them
}