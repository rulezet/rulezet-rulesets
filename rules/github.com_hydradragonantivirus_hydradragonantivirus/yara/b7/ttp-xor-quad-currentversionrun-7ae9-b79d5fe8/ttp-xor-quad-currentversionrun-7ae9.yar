rule TTP_XOR_QUAD_CurrentVersionRun_7ae9 {
  strings:
    $key_7ae9 = { 29 86 [2] 0d 88 [2] 26 a4 [2] 08 86 [2] 1c 9d [2] 13 87 [2] 0d 9a [2] 0f 9b [2] 14 9d [2] 08 9a [2] 14 b5 }

  condition:
    any of them
}