rule TTP_XOR_QUAD_CurrentVersionRun_7371 {
  strings:
    $key_7371 = { 20 1e [2] 04 10 [2] 2f 3c [2] 01 1e [2] 15 05 [2] 1a 1f [2] 04 02 [2] 06 03 [2] 1d 05 [2] 01 02 [2] 1d 2d }

  condition:
    any of them
}