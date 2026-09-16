rule TTP_XOR_QUAD_CurrentVersionRun_bd85 {
  strings:
    $key_bd85 = { ee ea [2] ca e4 [2] e1 c8 [2] cf ea [2] db f1 [2] d4 eb [2] ca f6 [2] c8 f7 [2] d3 f1 [2] cf f6 [2] d3 d9 }

  condition:
    any of them
}