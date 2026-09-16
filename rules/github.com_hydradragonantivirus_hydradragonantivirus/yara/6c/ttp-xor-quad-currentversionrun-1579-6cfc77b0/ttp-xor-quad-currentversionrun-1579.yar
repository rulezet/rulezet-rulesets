rule TTP_XOR_QUAD_CurrentVersionRun_1579 {
  strings:
    $key_1579 = { 46 16 [2] 62 18 [2] 49 34 [2] 67 16 [2] 73 0d [2] 7c 17 [2] 62 0a [2] 60 0b [2] 7b 0d [2] 67 0a [2] 7b 25 }

  condition:
    any of them
}