rule TTP_XOR_QUAD_CurrentVersionRun_44e9 {
  strings:
    $key_44e9 = { 17 86 [2] 33 88 [2] 18 a4 [2] 36 86 [2] 22 9d [2] 2d 87 [2] 33 9a [2] 31 9b [2] 2a 9d [2] 36 9a [2] 2a b5 }

  condition:
    any of them
}