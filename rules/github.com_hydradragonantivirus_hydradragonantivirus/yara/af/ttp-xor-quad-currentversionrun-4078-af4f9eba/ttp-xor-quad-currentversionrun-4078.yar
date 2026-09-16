rule TTP_XOR_QUAD_CurrentVersionRun_4078 {
  strings:
    $key_4078 = { 13 17 [2] 37 19 [2] 1c 35 [2] 32 17 [2] 26 0c [2] 29 16 [2] 37 0b [2] 35 0a [2] 2e 0c [2] 32 0b [2] 2e 24 }

  condition:
    any of them
}