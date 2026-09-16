rule TTP_XOR_QUAD_CurrentVersionRun_7421 {
  strings:
    $key_7421 = { 27 4e [2] 03 40 [2] 28 6c [2] 06 4e [2] 12 55 [2] 1d 4f [2] 03 52 [2] 01 53 [2] 1a 55 [2] 06 52 [2] 1a 7d }

  condition:
    any of them
}