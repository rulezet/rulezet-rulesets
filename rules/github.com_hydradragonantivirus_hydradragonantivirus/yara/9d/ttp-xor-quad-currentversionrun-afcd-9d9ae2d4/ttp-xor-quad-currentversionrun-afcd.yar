rule TTP_XOR_QUAD_CurrentVersionRun_afcd {
  strings:
    $key_afcd = { fc a2 [2] d8 ac [2] f3 80 [2] dd a2 [2] c9 b9 [2] c6 a3 [2] d8 be [2] da bf [2] c1 b9 [2] dd be [2] c1 91 }

  condition:
    any of them
}