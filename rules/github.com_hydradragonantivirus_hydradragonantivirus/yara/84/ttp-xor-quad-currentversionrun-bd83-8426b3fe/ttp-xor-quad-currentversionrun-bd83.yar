rule TTP_XOR_QUAD_CurrentVersionRun_bd83 {
  strings:
    $key_bd83 = { ee ec [2] ca e2 [2] e1 ce [2] cf ec [2] db f7 [2] d4 ed [2] ca f0 [2] c8 f1 [2] d3 f7 [2] cf f0 [2] d3 df }

  condition:
    any of them
}