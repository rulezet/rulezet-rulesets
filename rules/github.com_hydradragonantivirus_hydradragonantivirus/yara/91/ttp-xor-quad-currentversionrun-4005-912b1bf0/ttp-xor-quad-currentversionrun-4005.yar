rule TTP_XOR_QUAD_CurrentVersionRun_4005 {
  strings:
    $key_4005 = { 13 6a [2] 37 64 [2] 1c 48 [2] 32 6a [2] 26 71 [2] 29 6b [2] 37 76 [2] 35 77 [2] 2e 71 [2] 32 76 [2] 2e 59 }

  condition:
    any of them
}