rule TTP_XOR_QUAD_CurrentVersionRun_912a {
  strings:
    $key_912a = { c2 45 [2] e6 4b [2] cd 67 [2] e3 45 [2] f7 5e [2] f8 44 [2] e6 59 [2] e4 58 [2] ff 5e [2] e3 59 [2] ff 76 }

  condition:
    any of them
}