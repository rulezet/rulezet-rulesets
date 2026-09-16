rule TTP_XOR_QUAD_CurrentVersionRun_bdcc {
  strings:
    $key_bdcc = { ee a3 [2] ca ad [2] e1 81 [2] cf a3 [2] db b8 [2] d4 a2 [2] ca bf [2] c8 be [2] d3 b8 [2] cf bf [2] d3 90 }

  condition:
    any of them
}