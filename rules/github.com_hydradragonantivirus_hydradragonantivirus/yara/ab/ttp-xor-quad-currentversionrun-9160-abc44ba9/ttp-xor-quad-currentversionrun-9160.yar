rule TTP_XOR_QUAD_CurrentVersionRun_9160 {
  strings:
    $key_9160 = { c2 0f [2] e6 01 [2] cd 2d [2] e3 0f [2] f7 14 [2] f8 0e [2] e6 13 [2] e4 12 [2] ff 14 [2] e3 13 [2] ff 3c }

  condition:
    any of them
}