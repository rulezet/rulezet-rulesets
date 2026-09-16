rule TTP_XOR_QUAD_CurrentVersionRun_742c {
  strings:
    $key_742c = { 27 43 [2] 03 4d [2] 28 61 [2] 06 43 [2] 12 58 [2] 1d 42 [2] 03 5f [2] 01 5e [2] 1a 58 [2] 06 5f [2] 1a 70 }

  condition:
    any of them
}