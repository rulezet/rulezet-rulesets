rule TTP_XOR_QUAD_CurrentVersionRun_746a {
  strings:
    $key_746a = { 27 05 [2] 03 0b [2] 28 27 [2] 06 05 [2] 12 1e [2] 1d 04 [2] 03 19 [2] 01 18 [2] 1a 1e [2] 06 19 [2] 1a 36 }

  condition:
    any of them
}