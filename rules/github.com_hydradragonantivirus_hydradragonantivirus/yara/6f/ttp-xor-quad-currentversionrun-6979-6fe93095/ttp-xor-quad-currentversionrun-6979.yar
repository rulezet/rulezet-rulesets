rule TTP_XOR_QUAD_CurrentVersionRun_6979 {
  strings:
    $key_6979 = { 3a 16 [2] 1e 18 [2] 35 34 [2] 1b 16 [2] 0f 0d [2] 00 17 [2] 1e 0a [2] 1c 0b [2] 07 0d [2] 1b 0a [2] 07 25 }

  condition:
    any of them
}