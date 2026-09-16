rule TTP_XOR_QUAD_CurrentVersionRun_0267 {
  strings:
    $key_0267 = { 51 08 [2] 75 06 [2] 5e 2a [2] 70 08 [2] 64 13 [2] 6b 09 [2] 75 14 [2] 77 15 [2] 6c 13 [2] 70 14 [2] 6c 3b }

  condition:
    any of them
}