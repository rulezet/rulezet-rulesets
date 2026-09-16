rule TTP_XOR_QUAD_CurrentVersionRun_5e62 {
  strings:
    $key_5e62 = { 0d 0d [2] 29 03 [2] 02 2f [2] 2c 0d [2] 38 16 [2] 37 0c [2] 29 11 [2] 2b 10 [2] 30 16 [2] 2c 11 [2] 30 3e }

  condition:
    any of them
}