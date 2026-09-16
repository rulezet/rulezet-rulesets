rule TTP_XOR_QUAD_CurrentVersionRun_747c {
  strings:
    $key_747c = { 27 13 [2] 03 1d [2] 28 31 [2] 06 13 [2] 12 08 [2] 1d 12 [2] 03 0f [2] 01 0e [2] 1a 08 [2] 06 0f [2] 1a 20 }

  condition:
    any of them
}