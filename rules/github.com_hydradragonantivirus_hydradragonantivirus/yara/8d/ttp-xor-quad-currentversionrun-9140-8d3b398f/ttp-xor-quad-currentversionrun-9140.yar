rule TTP_XOR_QUAD_CurrentVersionRun_9140 {
  strings:
    $key_9140 = { c2 2f [2] e6 21 [2] cd 0d [2] e3 2f [2] f7 34 [2] f8 2e [2] e6 33 [2] e4 32 [2] ff 34 [2] e3 33 [2] ff 1c }

  condition:
    any of them
}