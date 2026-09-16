rule TTP_XOR_QUAD_CurrentVersionRun_7b62 {
  strings:
    $key_7b62 = { 28 0d [2] 0c 03 [2] 27 2f [2] 09 0d [2] 1d 16 [2] 12 0c [2] 0c 11 [2] 0e 10 [2] 15 16 [2] 09 11 [2] 15 3e }

  condition:
    any of them
}