rule TTP_XOR_QUAD_CurrentVersionRun_0975 {
  strings:
    $key_0975 = { 5a 1a [2] 7e 14 [2] 55 38 [2] 7b 1a [2] 6f 01 [2] 60 1b [2] 7e 06 [2] 7c 07 [2] 67 01 [2] 7b 06 [2] 67 29 }

  condition:
    any of them
}