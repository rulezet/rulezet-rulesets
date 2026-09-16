rule TTP_XOR_QUAD_CurrentVersionRun_912f {
  strings:
    $key_912f = { c2 40 [2] e6 4e [2] cd 62 [2] e3 40 [2] f7 5b [2] f8 41 [2] e6 5c [2] e4 5d [2] ff 5b [2] e3 5c [2] ff 73 }

  condition:
    any of them
}