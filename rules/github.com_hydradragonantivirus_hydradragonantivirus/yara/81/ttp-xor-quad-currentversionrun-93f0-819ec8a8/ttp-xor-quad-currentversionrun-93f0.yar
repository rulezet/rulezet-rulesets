rule TTP_XOR_QUAD_CurrentVersionRun_93f0 {
  strings:
    $key_93f0 = { c0 9f [2] e4 91 [2] cf bd [2] e1 9f [2] f5 84 [2] fa 9e [2] e4 83 [2] e6 82 [2] fd 84 [2] e1 83 [2] fd ac }

  condition:
    any of them
}