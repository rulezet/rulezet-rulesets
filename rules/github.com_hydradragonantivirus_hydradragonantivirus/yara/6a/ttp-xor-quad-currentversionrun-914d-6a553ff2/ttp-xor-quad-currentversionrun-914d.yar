rule TTP_XOR_QUAD_CurrentVersionRun_914d {
  strings:
    $key_914d = { c2 22 [2] e6 2c [2] cd 00 [2] e3 22 [2] f7 39 [2] f8 23 [2] e6 3e [2] e4 3f [2] ff 39 [2] e3 3e [2] ff 11 }

  condition:
    any of them
}