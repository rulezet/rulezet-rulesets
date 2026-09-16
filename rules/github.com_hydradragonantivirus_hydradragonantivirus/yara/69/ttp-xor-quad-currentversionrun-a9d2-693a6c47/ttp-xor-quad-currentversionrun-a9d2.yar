rule TTP_XOR_QUAD_CurrentVersionRun_a9d2 {
  strings:
    $key_a9d2 = { fa bd [2] de b3 [2] f5 9f [2] db bd [2] cf a6 [2] c0 bc [2] de a1 [2] dc a0 [2] c7 a6 [2] db a1 [2] c7 8e }

  condition:
    any of them
}