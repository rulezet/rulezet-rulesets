rule TTP_XOR_QUAD_CurrentVersionRun_7014 {
  strings:
    $key_7014 = { 23 7b [2] 07 75 [2] 2c 59 [2] 02 7b [2] 16 60 [2] 19 7a [2] 07 67 [2] 05 66 [2] 1e 60 [2] 02 67 [2] 1e 48 }

  condition:
    any of them
}