rule TTP_XOR_QUAD_CurrentVersionRun_6462 {
  strings:
    $key_6462 = { 37 0d [2] 13 03 [2] 38 2f [2] 16 0d [2] 02 16 [2] 0d 0c [2] 13 11 [2] 11 10 [2] 0a 16 [2] 16 11 [2] 0a 3e }

  condition:
    any of them
}