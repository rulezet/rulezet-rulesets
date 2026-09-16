rule TTP_XOR_QUAD_CurrentVersionRun_915c {
  strings:
    $key_915c = { c2 33 [2] e6 3d [2] cd 11 [2] e3 33 [2] f7 28 [2] f8 32 [2] e6 2f [2] e4 2e [2] ff 28 [2] e3 2f [2] ff 00 }

  condition:
    any of them
}