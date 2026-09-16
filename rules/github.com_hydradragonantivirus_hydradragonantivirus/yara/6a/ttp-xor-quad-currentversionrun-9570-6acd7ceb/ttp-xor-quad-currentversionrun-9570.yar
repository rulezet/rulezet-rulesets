rule TTP_XOR_QUAD_CurrentVersionRun_9570 {
  strings:
    $key_9570 = { c6 1f [2] e2 11 [2] c9 3d [2] e7 1f [2] f3 04 [2] fc 1e [2] e2 03 [2] e0 02 [2] fb 04 [2] e7 03 [2] fb 2c }

  condition:
    any of them
}