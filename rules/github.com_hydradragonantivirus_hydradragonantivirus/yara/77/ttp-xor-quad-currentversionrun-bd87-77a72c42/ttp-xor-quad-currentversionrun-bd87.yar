rule TTP_XOR_QUAD_CurrentVersionRun_bd87 {
  strings:
    $key_bd87 = { ee e8 [2] ca e6 [2] e1 ca [2] cf e8 [2] db f3 [2] d4 e9 [2] ca f4 [2] c8 f5 [2] d3 f3 [2] cf f4 [2] d3 db }

  condition:
    any of them
}