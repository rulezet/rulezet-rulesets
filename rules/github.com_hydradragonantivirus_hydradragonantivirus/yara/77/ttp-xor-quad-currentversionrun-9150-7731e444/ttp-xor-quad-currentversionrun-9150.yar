rule TTP_XOR_QUAD_CurrentVersionRun_9150 {
  strings:
    $key_9150 = { c2 3f [2] e6 31 [2] cd 1d [2] e3 3f [2] f7 24 [2] f8 3e [2] e6 23 [2] e4 22 [2] ff 24 [2] e3 23 [2] ff 0c }

  condition:
    any of them
}