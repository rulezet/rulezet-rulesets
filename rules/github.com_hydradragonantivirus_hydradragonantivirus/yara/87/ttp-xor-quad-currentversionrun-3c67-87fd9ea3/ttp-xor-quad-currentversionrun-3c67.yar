rule TTP_XOR_QUAD_CurrentVersionRun_3c67 {
  strings:
    $key_3c67 = { 6f 08 [2] 4b 06 [2] 60 2a [2] 4e 08 [2] 5a 13 [2] 55 09 [2] 4b 14 [2] 49 15 [2] 52 13 [2] 4e 14 [2] 52 3b }

  condition:
    any of them
}