rule TTP_XOR_QUAD_CurrentVersionRun_4716 {
  strings:
    $key_4716 = { 14 79 [2] 30 77 [2] 1b 5b [2] 35 79 [2] 21 62 [2] 2e 78 [2] 30 65 [2] 32 64 [2] 29 62 [2] 35 65 [2] 29 4a }

  condition:
    any of them
}