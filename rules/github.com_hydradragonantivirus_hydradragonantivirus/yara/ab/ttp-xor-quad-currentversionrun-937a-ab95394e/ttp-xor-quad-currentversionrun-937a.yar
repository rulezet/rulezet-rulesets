rule TTP_XOR_QUAD_CurrentVersionRun_937a {
  strings:
    $key_937a = { c0 15 [2] e4 1b [2] cf 37 [2] e1 15 [2] f5 0e [2] fa 14 [2] e4 09 [2] e6 08 [2] fd 0e [2] e1 09 [2] fd 26 }

  condition:
    any of them
}