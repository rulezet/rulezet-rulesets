rule TTP_XOR_QUAD_CurrentVersionRun_a6ba {
  strings:
    $key_a6ba = { f5 d5 [2] d1 db [2] fa f7 [2] d4 d5 [2] c0 ce [2] cf d4 [2] d1 c9 [2] d3 c8 [2] c8 ce [2] d4 c9 [2] c8 e6 }

  condition:
    any of them
}