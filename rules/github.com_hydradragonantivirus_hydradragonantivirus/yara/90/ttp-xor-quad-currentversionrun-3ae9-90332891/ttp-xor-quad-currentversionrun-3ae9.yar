rule TTP_XOR_QUAD_CurrentVersionRun_3ae9 {
  strings:
    $key_3ae9 = { 69 86 [2] 4d 88 [2] 66 a4 [2] 48 86 [2] 5c 9d [2] 53 87 [2] 4d 9a [2] 4f 9b [2] 54 9d [2] 48 9a [2] 54 b5 }

  condition:
    any of them
}