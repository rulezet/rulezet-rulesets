rule TTP_XOR_QUAD_CurrentVersionRun_933b {
  strings:
    $key_933b = { c0 54 [2] e4 5a [2] cf 76 [2] e1 54 [2] f5 4f [2] fa 55 [2] e4 48 [2] e6 49 [2] fd 4f [2] e1 48 [2] fd 67 }

  condition:
    any of them
}