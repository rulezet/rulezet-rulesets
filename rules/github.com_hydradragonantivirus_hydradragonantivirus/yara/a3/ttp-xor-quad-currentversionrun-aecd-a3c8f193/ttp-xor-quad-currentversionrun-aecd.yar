rule TTP_XOR_QUAD_CurrentVersionRun_aecd {
  strings:
    $key_aecd = { fd a2 [2] d9 ac [2] f2 80 [2] dc a2 [2] c8 b9 [2] c7 a3 [2] d9 be [2] db bf [2] c0 b9 [2] dc be [2] c0 91 }

  condition:
    any of them
}