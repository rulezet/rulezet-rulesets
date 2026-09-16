rule TTP_XOR_QUAD_CurrentVersionRun_6747 {
  strings:
    $key_6747 = { 34 28 [2] 10 26 [2] 3b 0a [2] 15 28 [2] 01 33 [2] 0e 29 [2] 10 34 [2] 12 35 [2] 09 33 [2] 15 34 [2] 09 1b }

  condition:
    any of them
}