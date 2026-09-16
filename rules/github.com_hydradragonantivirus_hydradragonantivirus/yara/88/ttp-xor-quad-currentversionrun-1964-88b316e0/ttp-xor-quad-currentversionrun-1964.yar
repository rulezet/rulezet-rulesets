rule TTP_XOR_QUAD_CurrentVersionRun_1964 {
  strings:
    $key_1964 = { 4a 0b [2] 6e 05 [2] 45 29 [2] 6b 0b [2] 7f 10 [2] 70 0a [2] 6e 17 [2] 6c 16 [2] 77 10 [2] 6b 17 [2] 77 38 }

  condition:
    any of them
}