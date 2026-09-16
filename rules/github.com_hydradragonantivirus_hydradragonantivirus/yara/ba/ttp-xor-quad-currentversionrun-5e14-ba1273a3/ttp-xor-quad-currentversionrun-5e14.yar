rule TTP_XOR_QUAD_CurrentVersionRun_5e14 {
  strings:
    $key_5e14 = { 0d 7b [2] 29 75 [2] 02 59 [2] 2c 7b [2] 38 60 [2] 37 7a [2] 29 67 [2] 2b 66 [2] 30 60 [2] 2c 67 [2] 30 48 }

  condition:
    any of them
}