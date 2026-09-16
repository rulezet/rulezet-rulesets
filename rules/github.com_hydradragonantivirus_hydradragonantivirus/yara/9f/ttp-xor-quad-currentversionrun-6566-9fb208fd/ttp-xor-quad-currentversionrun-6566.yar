rule TTP_XOR_QUAD_CurrentVersionRun_6566 {
  strings:
    $key_6566 = { 36 09 [2] 12 07 [2] 39 2b [2] 17 09 [2] 03 12 [2] 0c 08 [2] 12 15 [2] 10 14 [2] 0b 12 [2] 17 15 [2] 0b 3a }

  condition:
    any of them
}