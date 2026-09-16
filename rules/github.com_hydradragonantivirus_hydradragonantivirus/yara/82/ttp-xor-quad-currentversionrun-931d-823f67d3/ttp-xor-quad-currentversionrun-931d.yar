rule TTP_XOR_QUAD_CurrentVersionRun_931d {
  strings:
    $key_931d = { c0 72 [2] e4 7c [2] cf 50 [2] e1 72 [2] f5 69 [2] fa 73 [2] e4 6e [2] e6 6f [2] fd 69 [2] e1 6e [2] fd 41 }

  condition:
    any of them
}