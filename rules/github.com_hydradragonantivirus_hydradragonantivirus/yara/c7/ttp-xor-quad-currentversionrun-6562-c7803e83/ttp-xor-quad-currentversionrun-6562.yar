rule TTP_XOR_QUAD_CurrentVersionRun_6562 {
  strings:
    $key_6562 = { 36 0d [2] 12 03 [2] 39 2f [2] 17 0d [2] 03 16 [2] 0c 0c [2] 12 11 [2] 10 10 [2] 0b 16 [2] 17 11 [2] 0b 3e }

  condition:
    any of them
}