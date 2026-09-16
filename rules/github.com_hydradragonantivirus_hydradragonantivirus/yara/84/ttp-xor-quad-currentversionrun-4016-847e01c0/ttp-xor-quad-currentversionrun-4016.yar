rule TTP_XOR_QUAD_CurrentVersionRun_4016 {
  strings:
    $key_4016 = { 13 79 [2] 37 77 [2] 1c 5b [2] 32 79 [2] 26 62 [2] 29 78 [2] 37 65 [2] 35 64 [2] 2e 62 [2] 32 65 [2] 2e 4a }

  condition:
    any of them
}