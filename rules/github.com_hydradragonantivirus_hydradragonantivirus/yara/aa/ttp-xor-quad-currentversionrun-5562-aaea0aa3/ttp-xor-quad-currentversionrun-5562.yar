rule TTP_XOR_QUAD_CurrentVersionRun_5562 {
  strings:
    $key_5562 = { 06 0d [2] 22 03 [2] 09 2f [2] 27 0d [2] 33 16 [2] 3c 0c [2] 22 11 [2] 20 10 [2] 3b 16 [2] 27 11 [2] 3b 3e }

  condition:
    any of them
}