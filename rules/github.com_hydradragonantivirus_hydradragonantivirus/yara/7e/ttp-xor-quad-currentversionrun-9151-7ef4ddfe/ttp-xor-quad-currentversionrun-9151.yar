rule TTP_XOR_QUAD_CurrentVersionRun_9151 {
  strings:
    $key_9151 = { c2 3e [2] e6 30 [2] cd 1c [2] e3 3e [2] f7 25 [2] f8 3f [2] e6 22 [2] e4 23 [2] ff 25 [2] e3 22 [2] ff 0d }

  condition:
    any of them
}