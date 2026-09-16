rule TTP_XOR_QUAD_CurrentVersionRun_bd80 {
  strings:
    $key_bd80 = { ee ef [2] ca e1 [2] e1 cd [2] cf ef [2] db f4 [2] d4 ee [2] ca f3 [2] c8 f2 [2] d3 f4 [2] cf f3 [2] d3 dc }

  condition:
    any of them
}