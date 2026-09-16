rule TTP_XOR_QUAD_CurrentVersionRun_7966 {
  strings:
    $key_7966 = { 2a 09 [2] 0e 07 [2] 25 2b [2] 0b 09 [2] 1f 12 [2] 10 08 [2] 0e 15 [2] 0c 14 [2] 17 12 [2] 0b 15 [2] 17 3a }

  condition:
    any of them
}