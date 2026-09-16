rule TTP_XOR_QUAD_CurrentVersionRun_4cf8 {
  strings:
    $key_4cf8 = { 1f 97 [2] 3b 99 [2] 10 b5 [2] 3e 97 [2] 2a 8c [2] 25 96 [2] 3b 8b [2] 39 8a [2] 22 8c [2] 3e 8b [2] 22 a4 }

  condition:
    any of them
}