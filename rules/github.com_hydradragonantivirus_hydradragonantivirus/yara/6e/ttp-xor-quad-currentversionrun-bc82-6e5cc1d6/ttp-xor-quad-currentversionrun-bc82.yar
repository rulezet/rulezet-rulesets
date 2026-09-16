rule TTP_XOR_QUAD_CurrentVersionRun_bc82 {
  strings:
    $key_bc82 = { ef ed [2] cb e3 [2] e0 cf [2] ce ed [2] da f6 [2] d5 ec [2] cb f1 [2] c9 f0 [2] d2 f6 [2] ce f1 [2] d2 de }

  condition:
    any of them
}