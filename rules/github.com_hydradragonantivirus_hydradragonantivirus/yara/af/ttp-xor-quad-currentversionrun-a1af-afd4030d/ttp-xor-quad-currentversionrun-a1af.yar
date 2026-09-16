rule TTP_XOR_QUAD_CurrentVersionRun_a1af {
  strings:
    $key_a1af = { f2 c0 [2] d6 ce [2] fd e2 [2] d3 c0 [2] c7 db [2] c8 c1 [2] d6 dc [2] d4 dd [2] cf db [2] d3 dc [2] cf f3 }

  condition:
    any of them
}