rule TTP_XOR_QUAD_CurrentVersionRun_9162 {
  strings:
    $key_9162 = { c2 0d [2] e6 03 [2] cd 2f [2] e3 0d [2] f7 16 [2] f8 0c [2] e6 11 [2] e4 10 [2] ff 16 [2] e3 11 [2] ff 3e }

  condition:
    any of them
}