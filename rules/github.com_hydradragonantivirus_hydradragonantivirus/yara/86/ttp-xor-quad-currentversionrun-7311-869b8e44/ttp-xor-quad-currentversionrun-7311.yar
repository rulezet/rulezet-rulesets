rule TTP_XOR_QUAD_CurrentVersionRun_7311 {
  strings:
    $key_7311 = { 20 7e [2] 04 70 [2] 2f 5c [2] 01 7e [2] 15 65 [2] 1a 7f [2] 04 62 [2] 06 63 [2] 1d 65 [2] 01 62 [2] 1d 4d }

  condition:
    any of them
}