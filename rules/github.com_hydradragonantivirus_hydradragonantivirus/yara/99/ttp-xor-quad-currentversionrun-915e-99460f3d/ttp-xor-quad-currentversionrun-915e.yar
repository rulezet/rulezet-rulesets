rule TTP_XOR_QUAD_CurrentVersionRun_915e {
  strings:
    $key_915e = { c2 31 [2] e6 3f [2] cd 13 [2] e3 31 [2] f7 2a [2] f8 30 [2] e6 2d [2] e4 2c [2] ff 2a [2] e3 2d [2] ff 02 }

  condition:
    any of them
}