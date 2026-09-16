rule TTP_XOR_QUAD_CurrentVersionRun_935a {
  strings:
    $key_935a = { c0 35 [2] e4 3b [2] cf 17 [2] e1 35 [2] f5 2e [2] fa 34 [2] e4 29 [2] e6 28 [2] fd 2e [2] e1 29 [2] fd 06 }

  condition:
    any of them
}