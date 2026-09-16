rule TTP_XOR_QUAD_CurrentVersionRun_8ecd {
  strings:
    $key_8ecd = { dd a2 [2] f9 ac [2] d2 80 [2] fc a2 [2] e8 b9 [2] e7 a3 [2] f9 be [2] fb bf [2] e0 b9 [2] fc be [2] e0 91 }

  condition:
    any of them
}