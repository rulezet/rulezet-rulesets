rule TTP_XOR_QUAD_CurrentVersionRun_740c {
  strings:
    $key_740c = { 27 63 [2] 03 6d [2] 28 41 [2] 06 63 [2] 12 78 [2] 1d 62 [2] 03 7f [2] 01 7e [2] 1a 78 [2] 06 7f [2] 1a 50 }

  condition:
    any of them
}