rule TTP_XOR_QUAD_CurrentVersionRun_9341 {
  strings:
    $key_9341 = { c0 2e [2] e4 20 [2] cf 0c [2] e1 2e [2] f5 35 [2] fa 2f [2] e4 32 [2] e6 33 [2] fd 35 [2] e1 32 [2] fd 1d }

  condition:
    any of them
}