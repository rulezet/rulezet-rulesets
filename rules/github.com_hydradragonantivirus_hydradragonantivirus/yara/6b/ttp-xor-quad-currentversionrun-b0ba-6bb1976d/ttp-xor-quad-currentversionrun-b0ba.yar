rule TTP_XOR_QUAD_CurrentVersionRun_b0ba {
  strings:
    $key_b0ba = { e3 d5 [2] c7 db [2] ec f7 [2] c2 d5 [2] d6 ce [2] d9 d4 [2] c7 c9 [2] c5 c8 [2] de ce [2] c2 c9 [2] de e6 }

  condition:
    any of them
}