rule TTP_XOR_QUAD_CurrentVersionRun_93e1 {
  strings:
    $key_93e1 = { c0 8e [2] e4 80 [2] cf ac [2] e1 8e [2] f5 95 [2] fa 8f [2] e4 92 [2] e6 93 [2] fd 95 [2] e1 92 [2] fd bd }

  condition:
    any of them
}