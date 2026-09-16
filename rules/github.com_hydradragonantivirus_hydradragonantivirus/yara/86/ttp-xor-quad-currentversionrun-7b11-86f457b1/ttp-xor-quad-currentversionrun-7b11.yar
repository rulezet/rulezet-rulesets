rule TTP_XOR_QUAD_CurrentVersionRun_7b11 {
  strings:
    $key_7b11 = { 28 7e [2] 0c 70 [2] 27 5c [2] 09 7e [2] 1d 65 [2] 12 7f [2] 0c 62 [2] 0e 63 [2] 15 65 [2] 09 62 [2] 15 4d }

  condition:
    any of them
}