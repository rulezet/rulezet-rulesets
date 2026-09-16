rule TTP_XOR_QUAD_CurrentVersionRun_9120 {
  strings:
    $key_9120 = { c2 4f [2] e6 41 [2] cd 6d [2] e3 4f [2] f7 54 [2] f8 4e [2] e6 53 [2] e4 52 [2] ff 54 [2] e3 53 [2] ff 7c }

  condition:
    any of them
}