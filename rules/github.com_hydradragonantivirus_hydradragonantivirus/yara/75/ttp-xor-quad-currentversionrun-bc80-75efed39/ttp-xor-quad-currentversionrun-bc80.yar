rule TTP_XOR_QUAD_CurrentVersionRun_bc80 {
  strings:
    $key_bc80 = { ef ef [2] cb e1 [2] e0 cd [2] ce ef [2] da f4 [2] d5 ee [2] cb f3 [2] c9 f2 [2] d2 f4 [2] ce f3 [2] d2 dc }

  condition:
    any of them
}