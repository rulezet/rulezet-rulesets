rule TTP_XOR_QUAD_CurrentVersionRun_7ce5 {
  strings:
    $key_7ce5 = { 2f 8a [2] 0b 84 [2] 20 a8 [2] 0e 8a [2] 1a 91 [2] 15 8b [2] 0b 96 [2] 09 97 [2] 12 91 [2] 0e 96 [2] 12 b9 }

  condition:
    any of them
}