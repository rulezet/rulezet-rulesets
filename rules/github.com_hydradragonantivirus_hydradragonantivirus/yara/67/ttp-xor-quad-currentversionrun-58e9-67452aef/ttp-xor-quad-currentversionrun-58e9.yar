rule TTP_XOR_QUAD_CurrentVersionRun_58e9 {
  strings:
    $key_58e9 = { 0b 86 [2] 2f 88 [2] 04 a4 [2] 2a 86 [2] 3e 9d [2] 31 87 [2] 2f 9a [2] 2d 9b [2] 36 9d [2] 2a 9a [2] 36 b5 }

  condition:
    any of them
}