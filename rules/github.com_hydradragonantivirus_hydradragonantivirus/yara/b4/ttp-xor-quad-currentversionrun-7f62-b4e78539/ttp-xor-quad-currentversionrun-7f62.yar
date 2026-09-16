rule TTP_XOR_QUAD_CurrentVersionRun_7f62 {
  strings:
    $key_7f62 = { 2c 0d [2] 08 03 [2] 23 2f [2] 0d 0d [2] 19 16 [2] 16 0c [2] 08 11 [2] 0a 10 [2] 11 16 [2] 0d 11 [2] 11 3e }

  condition:
    any of them
}