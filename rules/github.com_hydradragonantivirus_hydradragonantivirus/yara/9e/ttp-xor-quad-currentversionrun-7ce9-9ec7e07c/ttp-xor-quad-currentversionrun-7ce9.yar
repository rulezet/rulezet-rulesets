rule TTP_XOR_QUAD_CurrentVersionRun_7ce9 {
  strings:
    $key_7ce9 = { 2f 86 [2] 0b 88 [2] 20 a4 [2] 0e 86 [2] 1a 9d [2] 15 87 [2] 0b 9a [2] 09 9b [2] 12 9d [2] 0e 9a [2] 12 b5 }

  condition:
    any of them
}