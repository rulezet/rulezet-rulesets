rule TTP_XOR_QUAD_CurrentVersionRun_0964 {
  strings:
    $key_0964 = { 5a 0b [2] 7e 05 [2] 55 29 [2] 7b 0b [2] 6f 10 [2] 60 0a [2] 7e 17 [2] 7c 16 [2] 67 10 [2] 7b 17 [2] 67 38 }

  condition:
    any of them
}