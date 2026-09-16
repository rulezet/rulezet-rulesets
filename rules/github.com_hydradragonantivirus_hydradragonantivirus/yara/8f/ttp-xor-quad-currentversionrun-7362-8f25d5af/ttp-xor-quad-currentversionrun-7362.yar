rule TTP_XOR_QUAD_CurrentVersionRun_7362 {
  strings:
    $key_7362 = { 20 0d [2] 04 03 [2] 2f 2f [2] 01 0d [2] 15 16 [2] 1a 0c [2] 04 11 [2] 06 10 [2] 1d 16 [2] 01 11 [2] 1d 3e }

  condition:
    any of them
}