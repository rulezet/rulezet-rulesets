rule TTP_XOR_QUAD_CurrentVersionRun_9370 {
  strings:
    $key_9370 = { c0 1f [2] e4 11 [2] cf 3d [2] e1 1f [2] f5 04 [2] fa 1e [2] e4 03 [2] e6 02 [2] fd 04 [2] e1 03 [2] fd 2c }

  condition:
    any of them
}