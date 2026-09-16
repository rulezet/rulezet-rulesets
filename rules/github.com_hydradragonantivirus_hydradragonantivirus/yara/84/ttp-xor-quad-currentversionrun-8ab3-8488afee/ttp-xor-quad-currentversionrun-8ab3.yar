rule TTP_XOR_QUAD_CurrentVersionRun_8ab3 {
  strings:
    $key_8ab3 = { d9 dc [2] fd d2 [2] d6 fe [2] f8 dc [2] ec c7 [2] e3 dd [2] fd c0 [2] ff c1 [2] e4 c7 [2] f8 c0 [2] e4 ef }

  condition:
    any of them
}