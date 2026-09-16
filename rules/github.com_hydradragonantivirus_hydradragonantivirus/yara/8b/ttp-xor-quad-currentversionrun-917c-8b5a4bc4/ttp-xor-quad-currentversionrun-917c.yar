rule TTP_XOR_QUAD_CurrentVersionRun_917c {
  strings:
    $key_917c = { c2 13 [2] e6 1d [2] cd 31 [2] e3 13 [2] f7 08 [2] f8 12 [2] e6 0f [2] e4 0e [2] ff 08 [2] e3 0f [2] ff 20 }

  condition:
    any of them
}