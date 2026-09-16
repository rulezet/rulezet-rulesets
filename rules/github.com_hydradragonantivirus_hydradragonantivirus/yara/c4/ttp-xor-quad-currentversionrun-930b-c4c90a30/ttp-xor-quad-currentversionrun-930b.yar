rule TTP_XOR_QUAD_CurrentVersionRun_930b {
  strings:
    $key_930b = { c0 64 [2] e4 6a [2] cf 46 [2] e1 64 [2] f5 7f [2] fa 65 [2] e4 78 [2] e6 79 [2] fd 7f [2] e1 78 [2] fd 57 }

  condition:
    any of them
}