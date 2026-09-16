rule TTP_XOR_QUAD_CurrentVersionRun_a0ba {
  strings:
    $key_a0ba = { f3 d5 [2] d7 db [2] fc f7 [2] d2 d5 [2] c6 ce [2] c9 d4 [2] d7 c9 [2] d5 c8 [2] ce ce [2] d2 c9 [2] ce e6 }

  condition:
    any of them
}