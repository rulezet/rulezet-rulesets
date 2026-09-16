rule TTP_XOR_QUAD_CurrentVersionRun_bdcd {
  strings:
    $key_bdcd = { ee a2 [2] ca ac [2] e1 80 [2] cf a2 [2] db b9 [2] d4 a3 [2] ca be [2] c8 bf [2] d3 b9 [2] cf be [2] d3 91 }

  condition:
    any of them
}