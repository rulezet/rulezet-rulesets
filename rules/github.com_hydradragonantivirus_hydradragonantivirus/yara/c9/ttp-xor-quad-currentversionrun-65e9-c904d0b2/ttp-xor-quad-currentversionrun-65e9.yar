rule TTP_XOR_QUAD_CurrentVersionRun_65e9 {
  strings:
    $key_65e9 = { 36 86 [2] 12 88 [2] 39 a4 [2] 17 86 [2] 03 9d [2] 0c 87 [2] 12 9a [2] 10 9b [2] 0b 9d [2] 17 9a [2] 0b b5 }

  condition:
    any of them
}