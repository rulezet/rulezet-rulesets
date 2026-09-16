rule TTP_XOR_QUAD_CurrentVersionRun_8db3 {
  strings:
    $key_8db3 = { de dc [2] fa d2 [2] d1 fe [2] ff dc [2] eb c7 [2] e4 dd [2] fa c0 [2] f8 c1 [2] e3 c7 [2] ff c0 [2] e3 ef }

  condition:
    any of them
}