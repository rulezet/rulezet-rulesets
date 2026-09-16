rule TTP_XOR_QUAD_CurrentVersionRun_7ee8 {
  strings:
    $key_7ee8 = { 2d 87 [2] 09 89 [2] 22 a5 [2] 0c 87 [2] 18 9c [2] 17 86 [2] 09 9b [2] 0b 9a [2] 10 9c [2] 0c 9b [2] 10 b4 }

  condition:
    any of them
}