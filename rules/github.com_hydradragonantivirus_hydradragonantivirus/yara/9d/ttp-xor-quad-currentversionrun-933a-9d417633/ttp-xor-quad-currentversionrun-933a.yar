rule TTP_XOR_QUAD_CurrentVersionRun_933a {
  strings:
    $key_933a = { c0 55 [2] e4 5b [2] cf 77 [2] e1 55 [2] f5 4e [2] fa 54 [2] e4 49 [2] e6 48 [2] fd 4e [2] e1 49 [2] fd 66 }

  condition:
    any of them
}