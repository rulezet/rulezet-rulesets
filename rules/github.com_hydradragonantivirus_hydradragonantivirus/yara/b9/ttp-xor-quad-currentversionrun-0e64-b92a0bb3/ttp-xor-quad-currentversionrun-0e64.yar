rule TTP_XOR_QUAD_CurrentVersionRun_0e64 {
  strings:
    $key_0e64 = { 5d 0b [2] 79 05 [2] 52 29 [2] 7c 0b [2] 68 10 [2] 67 0a [2] 79 17 [2] 7b 16 [2] 60 10 [2] 7c 17 [2] 60 38 }

  condition:
    any of them
}