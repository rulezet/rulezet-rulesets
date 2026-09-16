rule TTP_XOR_QUAD_CurrentVersionRun_8ab2 {
  strings:
    $key_8ab2 = { d9 dd [2] fd d3 [2] d6 ff [2] f8 dd [2] ec c6 [2] e3 dc [2] fd c1 [2] ff c0 [2] e4 c6 [2] f8 c1 [2] e4 ee }

  condition:
    any of them
}