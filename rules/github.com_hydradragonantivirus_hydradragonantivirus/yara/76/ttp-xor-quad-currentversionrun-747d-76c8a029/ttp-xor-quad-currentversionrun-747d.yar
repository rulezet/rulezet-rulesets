rule TTP_XOR_QUAD_CurrentVersionRun_747d {
  strings:
    $key_747d = { 27 12 [2] 03 1c [2] 28 30 [2] 06 12 [2] 12 09 [2] 1d 13 [2] 03 0e [2] 01 0f [2] 1a 09 [2] 06 0e [2] 1a 21 }

  condition:
    any of them
}