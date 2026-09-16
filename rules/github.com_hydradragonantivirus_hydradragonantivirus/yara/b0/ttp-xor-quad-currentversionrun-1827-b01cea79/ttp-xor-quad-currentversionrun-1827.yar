rule TTP_XOR_QUAD_CurrentVersionRun_1827 {
  strings:
    $key_1827 = { 4b 48 [2] 6f 46 [2] 44 6a [2] 6a 48 [2] 7e 53 [2] 71 49 [2] 6f 54 [2] 6d 55 [2] 76 53 [2] 6a 54 [2] 76 7b }

  condition:
    any of them
}