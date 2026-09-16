rule TTP_XOR_QUAD_CurrentVersionRun_5e02 {
  strings:
    $key_5e02 = { 0d 6d [2] 29 63 [2] 02 4f [2] 2c 6d [2] 38 76 [2] 37 6c [2] 29 71 [2] 2b 70 [2] 30 76 [2] 2c 71 [2] 30 5e }

  condition:
    any of them
}