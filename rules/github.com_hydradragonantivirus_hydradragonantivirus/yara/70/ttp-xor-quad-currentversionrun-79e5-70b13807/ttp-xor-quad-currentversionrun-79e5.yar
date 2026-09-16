rule TTP_XOR_QUAD_CurrentVersionRun_79e5 {
  strings:
    $key_79e5 = { 2a 8a [2] 0e 84 [2] 25 a8 [2] 0b 8a [2] 1f 91 [2] 10 8b [2] 0e 96 [2] 0c 97 [2] 17 91 [2] 0b 96 [2] 17 b9 }

  condition:
    any of them
}