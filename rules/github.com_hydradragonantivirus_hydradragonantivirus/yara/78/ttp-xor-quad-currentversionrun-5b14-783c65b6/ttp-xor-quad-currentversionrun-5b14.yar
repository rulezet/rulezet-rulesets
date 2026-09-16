rule TTP_XOR_QUAD_CurrentVersionRun_5b14 {
  strings:
    $key_5b14 = { 08 7b [2] 2c 75 [2] 07 59 [2] 29 7b [2] 3d 60 [2] 32 7a [2] 2c 67 [2] 2e 66 [2] 35 60 [2] 29 67 [2] 35 48 }

  condition:
    any of them
}