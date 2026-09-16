rule TTP_XOR_QUAD_CurrentVersionRun_6f62 {
  strings:
    $key_6f62 = { 3c 0d [2] 18 03 [2] 33 2f [2] 1d 0d [2] 09 16 [2] 06 0c [2] 18 11 [2] 1a 10 [2] 01 16 [2] 1d 11 [2] 01 3e }

  condition:
    any of them
}