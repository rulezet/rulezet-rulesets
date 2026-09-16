rule TTP_XOR_QUAD_CurrentVersionRun_4025 {
  strings:
    $key_4025 = { 13 4a [2] 37 44 [2] 1c 68 [2] 32 4a [2] 26 51 [2] 29 4b [2] 37 56 [2] 35 57 [2] 2e 51 [2] 32 56 [2] 2e 79 }

  condition:
    any of them
}