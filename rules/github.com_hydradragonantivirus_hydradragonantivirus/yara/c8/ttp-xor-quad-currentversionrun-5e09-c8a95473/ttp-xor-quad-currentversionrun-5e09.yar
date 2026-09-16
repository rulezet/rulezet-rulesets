rule TTP_XOR_QUAD_CurrentVersionRun_5e09 {
  strings:
    $key_5e09 = { 0d 66 [2] 29 68 [2] 02 44 [2] 2c 66 [2] 38 7d [2] 37 67 [2] 29 7a [2] 2b 7b [2] 30 7d [2] 2c 7a [2] 30 55 }

  condition:
    any of them
}