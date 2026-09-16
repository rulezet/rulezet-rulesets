rule TTP_XOR_QUAD_CurrentVersionRun_6066 {
  strings:
    $key_6066 = { 33 09 [2] 17 07 [2] 3c 2b [2] 12 09 [2] 06 12 [2] 09 08 [2] 17 15 [2] 15 14 [2] 0e 12 [2] 12 15 [2] 0e 3a }

  condition:
    any of them
}