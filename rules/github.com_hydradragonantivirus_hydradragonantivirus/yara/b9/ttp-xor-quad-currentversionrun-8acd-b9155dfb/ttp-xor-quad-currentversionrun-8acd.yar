rule TTP_XOR_QUAD_CurrentVersionRun_8acd {
  strings:
    $key_8acd = { d9 a2 [2] fd ac [2] d6 80 [2] f8 a2 [2] ec b9 [2] e3 a3 [2] fd be [2] ff bf [2] e4 b9 [2] f8 be [2] e4 91 }

  condition:
    any of them
}