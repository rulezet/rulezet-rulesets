rule TTP_XOR_QUAD_CurrentVersionRun_bd8a {
  strings:
    $key_bd8a = { ee e5 [2] ca eb [2] e1 c7 [2] cf e5 [2] db fe [2] d4 e4 [2] ca f9 [2] c8 f8 [2] d3 fe [2] cf f9 [2] d3 d6 }

  condition:
    any of them
}