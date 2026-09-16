rule TTP_XOR_QUAD_CurrentVersionRun_934a {
  strings:
    $key_934a = { c0 25 [2] e4 2b [2] cf 07 [2] e1 25 [2] f5 3e [2] fa 24 [2] e4 39 [2] e6 38 [2] fd 3e [2] e1 39 [2] fd 16 }

  condition:
    any of them
}