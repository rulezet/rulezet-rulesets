rule TTP_XOR_QUAD_CurrentVersionRun_88b3 {
  strings:
    $key_88b3 = { db dc [2] ff d2 [2] d4 fe [2] fa dc [2] ee c7 [2] e1 dd [2] ff c0 [2] fd c1 [2] e6 c7 [2] fa c0 [2] e6 ef }

  condition:
    any of them
}