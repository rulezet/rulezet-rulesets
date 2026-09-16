rule TTP_XOR_QUAD_CurrentVersionRun_a1ba {
  strings:
    $key_a1ba = { f2 d5 [2] d6 db [2] fd f7 [2] d3 d5 [2] c7 ce [2] c8 d4 [2] d6 c9 [2] d4 c8 [2] cf ce [2] d3 c9 [2] cf e6 }

  condition:
    any of them
}