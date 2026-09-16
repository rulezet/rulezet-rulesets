rule TTP_XOR_QUAD_CurrentVersionRun_3c64 {
  strings:
    $key_3c64 = { 6f 0b [2] 4b 05 [2] 60 29 [2] 4e 0b [2] 5a 10 [2] 55 0a [2] 4b 17 [2] 49 16 [2] 52 10 [2] 4e 17 [2] 52 38 }

  condition:
    any of them
}