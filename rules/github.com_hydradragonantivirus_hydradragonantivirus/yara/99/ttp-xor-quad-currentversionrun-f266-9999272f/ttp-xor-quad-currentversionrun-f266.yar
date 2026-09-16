rule TTP_XOR_QUAD_CurrentVersionRun_f266 {
  strings:
    $key_f266 = { a1 09 [2] 85 07 [2] ae 2b [2] 80 09 [2] 94 12 [2] 9b 08 [2] 85 15 [2] 87 14 [2] 9c 12 [2] 80 15 [2] 9c 3a }

  condition:
    any of them
}