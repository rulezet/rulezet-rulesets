rule TTP_XOR_QUAD_CurrentVersionRun_acd4 {
  strings:
    $key_acd4 = { ff bb [2] db b5 [2] f0 99 [2] de bb [2] ca a0 [2] c5 ba [2] db a7 [2] d9 a6 [2] c2 a0 [2] de a7 [2] c2 88 }

  condition:
    any of them
}