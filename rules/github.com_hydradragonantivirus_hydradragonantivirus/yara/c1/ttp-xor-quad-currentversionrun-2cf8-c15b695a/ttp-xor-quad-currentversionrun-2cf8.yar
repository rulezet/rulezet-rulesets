rule TTP_XOR_QUAD_CurrentVersionRun_2cf8 {
  strings:
    $key_2cf8 = { 7f 97 [2] 5b 99 [2] 70 b5 [2] 5e 97 [2] 4a 8c [2] 45 96 [2] 5b 8b [2] 59 8a [2] 42 8c [2] 5e 8b [2] 42 a4 }

  condition:
    any of them
}