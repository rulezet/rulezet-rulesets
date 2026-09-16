rule TTP_XOR_QUAD_CurrentVersionRun_9470 {
  strings:
    $key_9470 = { c7 1f [2] e3 11 [2] c8 3d [2] e6 1f [2] f2 04 [2] fd 1e [2] e3 03 [2] e1 02 [2] fa 04 [2] e6 03 [2] fa 2c }

  condition:
    any of them
}