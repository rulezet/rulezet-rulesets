rule TTP_XOR_QUAD_CurrentVersionRun_bdc0 {
  strings:
    $key_bdc0 = { ee af [2] ca a1 [2] e1 8d [2] cf af [2] db b4 [2] d4 ae [2] ca b3 [2] c8 b2 [2] d3 b4 [2] cf b3 [2] d3 9c }

  condition:
    any of them
}