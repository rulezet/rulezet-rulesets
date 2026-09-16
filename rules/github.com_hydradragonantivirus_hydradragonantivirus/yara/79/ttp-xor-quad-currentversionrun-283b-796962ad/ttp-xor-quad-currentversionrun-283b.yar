rule TTP_XOR_QUAD_CurrentVersionRun_283b {
  strings:
    $key_283b = { 7b 54 [2] 5f 5a [2] 74 76 [2] 5a 54 [2] 4e 4f [2] 41 55 [2] 5f 48 [2] 5d 49 [2] 46 4f [2] 5a 48 [2] 46 67 }

  condition:
    any of them
}