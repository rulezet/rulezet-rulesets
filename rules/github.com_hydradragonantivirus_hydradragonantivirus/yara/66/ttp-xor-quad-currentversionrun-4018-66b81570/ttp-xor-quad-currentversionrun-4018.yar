rule TTP_XOR_QUAD_CurrentVersionRun_4018 {
  strings:
    $key_4018 = { 13 77 [2] 37 79 [2] 1c 55 [2] 32 77 [2] 26 6c [2] 29 76 [2] 37 6b [2] 35 6a [2] 2e 6c [2] 32 6b [2] 2e 44 }

  condition:
    any of them
}