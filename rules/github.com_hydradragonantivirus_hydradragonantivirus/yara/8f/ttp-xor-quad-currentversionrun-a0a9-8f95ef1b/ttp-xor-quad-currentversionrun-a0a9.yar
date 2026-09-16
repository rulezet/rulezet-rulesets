rule TTP_XOR_QUAD_CurrentVersionRun_a0a9 {
  strings:
    $key_a0a9 = { f3 c6 [2] d7 c8 [2] fc e4 [2] d2 c6 [2] c6 dd [2] c9 c7 [2] d7 da [2] d5 db [2] ce dd [2] d2 da [2] ce f5 }

  condition:
    any of them
}