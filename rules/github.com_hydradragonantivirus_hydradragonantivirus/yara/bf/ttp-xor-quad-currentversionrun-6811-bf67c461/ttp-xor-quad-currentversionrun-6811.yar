rule TTP_XOR_QUAD_CurrentVersionRun_6811 {
  strings:
    $key_6811 = { 3b 7e [2] 1f 70 [2] 34 5c [2] 1a 7e [2] 0e 65 [2] 01 7f [2] 1f 62 [2] 1d 63 [2] 06 65 [2] 1a 62 [2] 06 4d }

  condition:
    any of them
}