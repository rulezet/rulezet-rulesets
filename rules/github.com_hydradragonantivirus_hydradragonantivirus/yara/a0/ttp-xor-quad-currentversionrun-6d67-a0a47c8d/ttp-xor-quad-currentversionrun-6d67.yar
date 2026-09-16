rule TTP_XOR_QUAD_CurrentVersionRun_6d67 {
  strings:
    $key_6d67 = { 3e 08 [2] 1a 06 [2] 31 2a [2] 1f 08 [2] 0b 13 [2] 04 09 [2] 1a 14 [2] 18 15 [2] 03 13 [2] 1f 14 [2] 03 3b }

  condition:
    any of them
}