rule TTP_XOR_QUAD_CurrentVersionRun_4514 {
  strings:
    $key_4514 = { 16 7b [2] 32 75 [2] 19 59 [2] 37 7b [2] 23 60 [2] 2c 7a [2] 32 67 [2] 30 66 [2] 2b 60 [2] 37 67 [2] 2b 48 }

  condition:
    any of them
}