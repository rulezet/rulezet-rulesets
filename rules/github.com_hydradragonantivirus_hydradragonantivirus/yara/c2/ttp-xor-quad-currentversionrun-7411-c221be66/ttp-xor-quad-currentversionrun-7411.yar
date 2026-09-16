rule TTP_XOR_QUAD_CurrentVersionRun_7411 {
  strings:
    $key_7411 = { 27 7e [2] 03 70 [2] 28 5c [2] 06 7e [2] 12 65 [2] 1d 7f [2] 03 62 [2] 01 63 [2] 1a 65 [2] 06 62 [2] 1a 4d }

  condition:
    any of them
}