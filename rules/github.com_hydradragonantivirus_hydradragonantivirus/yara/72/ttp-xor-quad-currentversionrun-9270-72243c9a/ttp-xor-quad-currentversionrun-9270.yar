rule TTP_XOR_QUAD_CurrentVersionRun_9270 {
  strings:
    $key_9270 = { c1 1f [2] e5 11 [2] ce 3d [2] e0 1f [2] f4 04 [2] fb 1e [2] e5 03 [2] e7 02 [2] fc 04 [2] e0 03 [2] fc 2c }

  condition:
    any of them
}