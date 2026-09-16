rule TTP_XOR_QUAD_CurrentVersionRun_6267 {
  strings:
    $key_6267 = { 31 08 [2] 15 06 [2] 3e 2a [2] 10 08 [2] 04 13 [2] 0b 09 [2] 15 14 [2] 17 15 [2] 0c 13 [2] 10 14 [2] 0c 3b }

  condition:
    any of them
}