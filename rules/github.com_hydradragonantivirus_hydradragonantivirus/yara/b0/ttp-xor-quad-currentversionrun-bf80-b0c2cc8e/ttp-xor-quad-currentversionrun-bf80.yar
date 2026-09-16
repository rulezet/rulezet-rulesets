rule TTP_XOR_QUAD_CurrentVersionRun_bf80 {
  strings:
    $key_bf80 = { ec ef [2] c8 e1 [2] e3 cd [2] cd ef [2] d9 f4 [2] d6 ee [2] c8 f3 [2] ca f2 [2] d1 f4 [2] cd f3 [2] d1 dc }

  condition:
    any of them
}