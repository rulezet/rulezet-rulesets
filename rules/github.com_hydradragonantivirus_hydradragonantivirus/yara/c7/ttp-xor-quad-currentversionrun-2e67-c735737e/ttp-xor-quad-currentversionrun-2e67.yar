rule TTP_XOR_QUAD_CurrentVersionRun_2e67 {
  strings:
    $key_2e67 = { 7d 08 [2] 59 06 [2] 72 2a [2] 5c 08 [2] 48 13 [2] 47 09 [2] 59 14 [2] 5b 15 [2] 40 13 [2] 5c 14 [2] 40 3b }

  condition:
    any of them
}