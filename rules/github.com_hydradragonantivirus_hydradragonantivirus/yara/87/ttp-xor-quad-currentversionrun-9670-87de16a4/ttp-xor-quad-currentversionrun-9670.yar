rule TTP_XOR_QUAD_CurrentVersionRun_9670 {
  strings:
    $key_9670 = { c5 1f [2] e1 11 [2] ca 3d [2] e4 1f [2] f0 04 [2] ff 1e [2] e1 03 [2] e3 02 [2] f8 04 [2] e4 03 [2] f8 2c }

  condition:
    any of them
}