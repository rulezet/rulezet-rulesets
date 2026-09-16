rule TTP_XOR_QUAD_CurrentVersionRun_7410 {
  strings:
    $key_7410 = { 27 7f [2] 03 71 [2] 28 5d [2] 06 7f [2] 12 64 [2] 1d 7e [2] 03 63 [2] 01 62 [2] 1a 64 [2] 06 63 [2] 1a 4c }

  condition:
    any of them
}