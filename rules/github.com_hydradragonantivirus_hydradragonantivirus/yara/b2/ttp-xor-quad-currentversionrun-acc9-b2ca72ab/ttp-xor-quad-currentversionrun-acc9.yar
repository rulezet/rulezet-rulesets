rule TTP_XOR_QUAD_CurrentVersionRun_acc9 {
  strings:
    $key_acc9 = { ff a6 [2] db a8 [2] f0 84 [2] de a6 [2] ca bd [2] c5 a7 [2] db ba [2] d9 bb [2] c2 bd [2] de ba [2] c2 95 }

  condition:
    any of them
}