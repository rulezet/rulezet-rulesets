rule TTP_XOR_QUAD_CurrentVersionRun_3c46 {
  strings:
    $key_3c46 = { 6f 29 [2] 4b 27 [2] 60 0b [2] 4e 29 [2] 5a 32 [2] 55 28 [2] 4b 35 [2] 49 34 [2] 52 32 [2] 4e 35 [2] 52 1a }

  condition:
    any of them
}