rule TTP_XOR_QUAD_CurrentVersionRun_bd9c {
  strings:
    $key_bd9c = { ee f3 [2] ca fd [2] e1 d1 [2] cf f3 [2] db e8 [2] d4 f2 [2] ca ef [2] c8 ee [2] d3 e8 [2] cf ef [2] d3 c0 }

  condition:
    any of them
}