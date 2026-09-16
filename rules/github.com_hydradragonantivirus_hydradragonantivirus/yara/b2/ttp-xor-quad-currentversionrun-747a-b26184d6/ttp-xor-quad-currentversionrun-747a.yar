rule TTP_XOR_QUAD_CurrentVersionRun_747a {
  strings:
    $key_747a = { 27 15 [2] 03 1b [2] 28 37 [2] 06 15 [2] 12 0e [2] 1d 14 [2] 03 09 [2] 01 08 [2] 1a 0e [2] 06 09 [2] 1a 26 }

  condition:
    any of them
}