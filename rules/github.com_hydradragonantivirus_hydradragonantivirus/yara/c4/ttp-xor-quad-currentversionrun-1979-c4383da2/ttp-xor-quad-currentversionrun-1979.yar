rule TTP_XOR_QUAD_CurrentVersionRun_1979 {
  strings:
    $key_1979 = { 4a 16 [2] 6e 18 [2] 45 34 [2] 6b 16 [2] 7f 0d [2] 70 17 [2] 6e 0a [2] 6c 0b [2] 77 0d [2] 6b 0a [2] 77 25 }

  condition:
    any of them
}