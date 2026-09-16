rule TTP_XOR_QUAD_CurrentVersionRun_2967 {
  strings:
    $key_2967 = { 7a 08 [2] 5e 06 [2] 75 2a [2] 5b 08 [2] 4f 13 [2] 40 09 [2] 5e 14 [2] 5c 15 [2] 47 13 [2] 5b 14 [2] 47 3b }

  condition:
    any of them
}