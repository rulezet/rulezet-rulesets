rule TTP_XOR_QUAD_CurrentVersionRun_23e9 {
  strings:
    $key_23e9 = { 70 86 [2] 54 88 [2] 7f a4 [2] 51 86 [2] 45 9d [2] 4a 87 [2] 54 9a [2] 56 9b [2] 4d 9d [2] 51 9a [2] 4d b5 }

  condition:
    any of them
}