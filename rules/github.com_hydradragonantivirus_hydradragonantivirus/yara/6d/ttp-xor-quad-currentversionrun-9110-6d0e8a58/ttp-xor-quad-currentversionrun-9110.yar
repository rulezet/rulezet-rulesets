rule TTP_XOR_QUAD_CurrentVersionRun_9110 {
  strings:
    $key_9110 = { c2 7f [2] e6 71 [2] cd 5d [2] e3 7f [2] f7 64 [2] f8 7e [2] e6 63 [2] e4 62 [2] ff 64 [2] e3 63 [2] ff 4c }

  condition:
    any of them
}