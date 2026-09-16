rule TTP_XOR_QUAD_CurrentVersionRun_acc8 {
  strings:
    $key_acc8 = { ff a7 [2] db a9 [2] f0 85 [2] de a7 [2] ca bc [2] c5 a6 [2] db bb [2] d9 ba [2] c2 bc [2] de bb [2] c2 94 }

  condition:
    any of them
}