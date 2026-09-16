rule TTP_XOR_QUAD_CurrentVersionRun_fecd {
  strings:
    $key_fecd = { ad a2 [2] 89 ac [2] a2 80 [2] 8c a2 [2] 98 b9 [2] 97 a3 [2] 89 be [2] 8b bf [2] 90 b9 [2] 8c be [2] 90 91 }

  condition:
    any of them
}