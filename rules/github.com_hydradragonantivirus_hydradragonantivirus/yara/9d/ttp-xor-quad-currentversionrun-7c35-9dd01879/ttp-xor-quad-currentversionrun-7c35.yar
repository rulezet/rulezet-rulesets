rule TTP_XOR_QUAD_CurrentVersionRun_7c35 {
  strings:
    $key_7c35 = { 2f 5a [2] 0b 54 [2] 20 78 [2] 0e 5a [2] 1a 41 [2] 15 5b [2] 0b 46 [2] 09 47 [2] 12 41 [2] 0e 46 [2] 12 69 }

  condition:
    any of them
}