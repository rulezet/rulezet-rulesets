rule TTP_XOR_QUAD_CurrentVersionRun_6766 {
  strings:
    $key_6766 = { 34 09 [2] 10 07 [2] 3b 2b [2] 15 09 [2] 01 12 [2] 0e 08 [2] 10 15 [2] 12 14 [2] 09 12 [2] 15 15 [2] 09 3a }

  condition:
    any of them
}