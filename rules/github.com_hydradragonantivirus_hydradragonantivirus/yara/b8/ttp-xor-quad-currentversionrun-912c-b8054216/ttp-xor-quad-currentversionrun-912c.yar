rule TTP_XOR_QUAD_CurrentVersionRun_912c {
  strings:
    $key_912c = { c2 43 [2] e6 4d [2] cd 61 [2] e3 43 [2] f7 58 [2] f8 42 [2] e6 5f [2] e4 5e [2] ff 58 [2] e3 5f [2] ff 70 }

  condition:
    any of them
}