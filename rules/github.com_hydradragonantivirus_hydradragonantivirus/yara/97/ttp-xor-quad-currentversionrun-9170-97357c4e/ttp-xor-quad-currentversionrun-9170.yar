rule TTP_XOR_QUAD_CurrentVersionRun_9170 {
  strings:
    $key_9170 = { c2 1f [2] e6 11 [2] cd 3d [2] e3 1f [2] f7 04 [2] f8 1e [2] e6 03 [2] e4 02 [2] ff 04 [2] e3 03 [2] ff 2c }

  condition:
    any of them
}