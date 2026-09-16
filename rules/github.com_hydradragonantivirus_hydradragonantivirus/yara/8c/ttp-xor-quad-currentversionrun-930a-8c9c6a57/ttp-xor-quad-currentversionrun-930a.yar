rule TTP_XOR_QUAD_CurrentVersionRun_930a {
  strings:
    $key_930a = { c0 65 [2] e4 6b [2] cf 47 [2] e1 65 [2] f5 7e [2] fa 64 [2] e4 79 [2] e6 78 [2] fd 7e [2] e1 79 [2] fd 56 }

  condition:
    any of them
}