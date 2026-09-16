rule TTP_XOR_QUAD_CurrentVersionRun_746c {
  strings:
    $key_746c = { 27 03 [2] 03 0d [2] 28 21 [2] 06 03 [2] 12 18 [2] 1d 02 [2] 03 1f [2] 01 1e [2] 1a 18 [2] 06 1f [2] 1a 30 }

  condition:
    any of them
}