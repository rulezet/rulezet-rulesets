rule TTP_XOR_QUAD_CurrentVersionRun_5de5 {
  strings:
    $key_5de5 = { 0e 8a [2] 2a 84 [2] 01 a8 [2] 2f 8a [2] 3b 91 [2] 34 8b [2] 2a 96 [2] 28 97 [2] 33 91 [2] 2f 96 [2] 33 b9 }

  condition:
    any of them
}