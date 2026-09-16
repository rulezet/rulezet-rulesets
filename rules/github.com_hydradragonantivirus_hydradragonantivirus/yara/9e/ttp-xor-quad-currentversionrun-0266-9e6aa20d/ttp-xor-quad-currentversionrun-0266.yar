rule TTP_XOR_QUAD_CurrentVersionRun_0266 {
  strings:
    $key_0266 = { 51 09 [2] 75 07 [2] 5e 2b [2] 70 09 [2] 64 12 [2] 6b 08 [2] 75 15 [2] 77 14 [2] 6c 12 [2] 70 15 [2] 6c 3a }

  condition:
    any of them
}