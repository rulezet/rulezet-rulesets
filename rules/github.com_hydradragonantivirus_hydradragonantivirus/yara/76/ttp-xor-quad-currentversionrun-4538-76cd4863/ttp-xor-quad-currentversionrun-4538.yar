rule TTP_XOR_QUAD_CurrentVersionRun_4538 {
  strings:
    $key_4538 = { 16 57 [2] 32 59 [2] 19 75 [2] 37 57 [2] 23 4c [2] 2c 56 [2] 32 4b [2] 30 4a [2] 2b 4c [2] 37 4b [2] 2b 64 }

  condition:
    any of them
}