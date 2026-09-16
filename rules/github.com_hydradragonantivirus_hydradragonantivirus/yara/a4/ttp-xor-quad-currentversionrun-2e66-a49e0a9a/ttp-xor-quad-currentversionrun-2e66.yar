rule TTP_XOR_QUAD_CurrentVersionRun_2e66 {
  strings:
    $key_2e66 = { 7d 09 [2] 59 07 [2] 72 2b [2] 5c 09 [2] 48 12 [2] 47 08 [2] 59 15 [2] 5b 14 [2] 40 12 [2] 5c 15 [2] 40 3a }

  condition:
    any of them
}