rule TTP_XOR_QUAD_CurrentVersionRun_916f {
  strings:
    $key_916f = { c2 00 [2] e6 0e [2] cd 22 [2] e3 00 [2] f7 1b [2] f8 01 [2] e6 1c [2] e4 1d [2] ff 1b [2] e3 1c [2] ff 33 }

  condition:
    any of them
}