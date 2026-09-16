rule TTP_XOR_QUAD_CurrentVersionRun_917d {
  strings:
    $key_917d = { c2 12 [2] e6 1c [2] cd 30 [2] e3 12 [2] f7 09 [2] f8 13 [2] e6 0e [2] e4 0f [2] ff 09 [2] e3 0e [2] ff 21 }

  condition:
    any of them
}