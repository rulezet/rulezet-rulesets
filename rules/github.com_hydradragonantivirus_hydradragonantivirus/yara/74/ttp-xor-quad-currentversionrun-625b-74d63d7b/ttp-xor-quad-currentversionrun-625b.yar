rule TTP_XOR_QUAD_CurrentVersionRun_625b {
  strings:
    $key_625b = { 31 34 [2] 15 3a [2] 3e 16 [2] 10 34 [2] 04 2f [2] 0b 35 [2] 15 28 [2] 17 29 [2] 0c 2f [2] 10 28 [2] 0c 07 }

  condition:
    any of them
}