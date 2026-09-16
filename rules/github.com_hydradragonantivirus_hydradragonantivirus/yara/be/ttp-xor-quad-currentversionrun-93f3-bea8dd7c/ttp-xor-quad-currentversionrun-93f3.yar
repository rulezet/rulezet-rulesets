rule TTP_XOR_QUAD_CurrentVersionRun_93f3 {
  strings:
    $key_93f3 = { c0 9c [2] e4 92 [2] cf be [2] e1 9c [2] f5 87 [2] fa 9d [2] e4 80 [2] e6 81 [2] fd 87 [2] e1 80 [2] fd af }

  condition:
    any of them
}