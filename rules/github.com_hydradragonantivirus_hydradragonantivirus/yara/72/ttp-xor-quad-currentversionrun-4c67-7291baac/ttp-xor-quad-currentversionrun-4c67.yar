rule TTP_XOR_QUAD_CurrentVersionRun_4c67 {
  strings:
    $key_4c67 = { 1f 08 [2] 3b 06 [2] 10 2a [2] 3e 08 [2] 2a 13 [2] 25 09 [2] 3b 14 [2] 39 15 [2] 22 13 [2] 3e 14 [2] 22 3b }

  condition:
    any of them
}