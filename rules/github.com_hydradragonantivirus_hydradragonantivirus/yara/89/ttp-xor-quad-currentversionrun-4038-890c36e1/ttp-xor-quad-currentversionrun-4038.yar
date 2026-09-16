rule TTP_XOR_QUAD_CurrentVersionRun_4038 {
  strings:
    $key_4038 = { 13 57 [2] 37 59 [2] 1c 75 [2] 32 57 [2] 26 4c [2] 29 56 [2] 37 4b [2] 35 4a [2] 2e 4c [2] 32 4b [2] 2e 64 }

  condition:
    any of them
}