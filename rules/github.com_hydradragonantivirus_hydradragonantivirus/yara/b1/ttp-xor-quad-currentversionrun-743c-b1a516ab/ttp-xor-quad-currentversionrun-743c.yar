rule TTP_XOR_QUAD_CurrentVersionRun_743c {
  strings:
    $key_743c = { 27 53 [2] 03 5d [2] 28 71 [2] 06 53 [2] 12 48 [2] 1d 52 [2] 03 4f [2] 01 4e [2] 1a 48 [2] 06 4f [2] 1a 60 }

  condition:
    any of them
}