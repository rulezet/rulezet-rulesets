rule TTP_XOR_QUAD_CurrentVersionRun_3fe9 {
  strings:
    $key_3fe9 = { 6c 86 [2] 48 88 [2] 63 a4 [2] 4d 86 [2] 59 9d [2] 56 87 [2] 48 9a [2] 4a 9b [2] 51 9d [2] 4d 9a [2] 51 b5 }

  condition:
    any of them
}