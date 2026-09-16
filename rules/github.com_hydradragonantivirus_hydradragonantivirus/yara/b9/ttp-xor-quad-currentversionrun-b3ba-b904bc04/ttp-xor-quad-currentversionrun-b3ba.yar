rule TTP_XOR_QUAD_CurrentVersionRun_b3ba {
  strings:
    $key_b3ba = { e0 d5 [2] c4 db [2] ef f7 [2] c1 d5 [2] d5 ce [2] da d4 [2] c4 c9 [2] c6 c8 [2] dd ce [2] c1 c9 [2] dd e6 }

  condition:
    any of them
}