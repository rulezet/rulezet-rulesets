rule TTP_XOR_QUAD_CurrentVersionRun_9301 {
  strings:
    $key_9301 = { c0 6e [2] e4 60 [2] cf 4c [2] e1 6e [2] f5 75 [2] fa 6f [2] e4 72 [2] e6 73 [2] fd 75 [2] e1 72 [2] fd 5d }

  condition:
    any of them
}