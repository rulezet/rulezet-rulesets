rule TTP_XOR_QUAD_CurrentVersionRun_5df9 {
  strings:
    $key_5df9 = { 0e 96 [2] 2a 98 [2] 01 b4 [2] 2f 96 [2] 3b 8d [2] 34 97 [2] 2a 8a [2] 28 8b [2] 33 8d [2] 2f 8a [2] 33 a5 }

  condition:
    any of them
}