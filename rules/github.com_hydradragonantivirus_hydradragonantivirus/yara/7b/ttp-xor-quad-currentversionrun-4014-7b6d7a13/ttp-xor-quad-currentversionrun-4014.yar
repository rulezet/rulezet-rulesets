rule TTP_XOR_QUAD_CurrentVersionRun_4014 {
  strings:
    $key_4014 = { 13 7b [2] 37 75 [2] 1c 59 [2] 32 7b [2] 26 60 [2] 29 7a [2] 37 67 [2] 35 66 [2] 2e 60 [2] 32 67 [2] 2e 48 }

  condition:
    any of them
}