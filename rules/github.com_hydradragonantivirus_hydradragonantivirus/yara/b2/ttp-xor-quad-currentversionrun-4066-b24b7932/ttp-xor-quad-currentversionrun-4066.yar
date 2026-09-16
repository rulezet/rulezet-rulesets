rule TTP_XOR_QUAD_CurrentVersionRun_4066 {
  strings:
    $key_4066 = { 13 09 [2] 37 07 [2] 1c 2b [2] 32 09 [2] 26 12 [2] 29 08 [2] 37 15 [2] 35 14 [2] 2e 12 [2] 32 15 [2] 2e 3a }

  condition:
    any of them
}