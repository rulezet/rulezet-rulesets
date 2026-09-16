rule TTP_XOR_QUAD_CurrentVersionRun_7432 {
  strings:
    $key_7432 = { 27 5d [2] 03 53 [2] 28 7f [2] 06 5d [2] 12 46 [2] 1d 5c [2] 03 41 [2] 01 40 [2] 1a 46 [2] 06 41 [2] 1a 6e }

  condition:
    any of them
}