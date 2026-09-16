rule TTP_XOR_QUAD_CurrentVersionRun_a9db {
  strings:
    $key_a9db = { fa b4 [2] de ba [2] f5 96 [2] db b4 [2] cf af [2] c0 b5 [2] de a8 [2] dc a9 [2] c7 af [2] db a8 [2] c7 87 }

  condition:
    any of them
}