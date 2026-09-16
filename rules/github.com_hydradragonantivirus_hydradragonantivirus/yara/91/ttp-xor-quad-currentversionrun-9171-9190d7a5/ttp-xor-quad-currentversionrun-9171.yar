rule TTP_XOR_QUAD_CurrentVersionRun_9171 {
  strings:
    $key_9171 = { c2 1e [2] e6 10 [2] cd 3c [2] e3 1e [2] f7 05 [2] f8 1f [2] e6 02 [2] e4 03 [2] ff 05 [2] e3 02 [2] ff 2d }

  condition:
    any of them
}