rule TTP_XOR_QUAD_CurrentVersionRun_a0af {
  strings:
    $key_a0af = { f3 c0 [2] d7 ce [2] fc e2 [2] d2 c0 [2] c6 db [2] c9 c1 [2] d7 dc [2] d5 dd [2] ce db [2] d2 dc [2] ce f3 }

  condition:
    any of them
}