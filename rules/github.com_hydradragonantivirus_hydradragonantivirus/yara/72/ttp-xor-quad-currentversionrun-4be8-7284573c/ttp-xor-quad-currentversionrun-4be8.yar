rule TTP_XOR_QUAD_CurrentVersionRun_4be8 {
  strings:
    $key_4be8 = { 18 87 [2] 3c 89 [2] 17 a5 [2] 39 87 [2] 2d 9c [2] 22 86 [2] 3c 9b [2] 3e 9a [2] 25 9c [2] 39 9b [2] 25 b4 }

  condition:
    any of them
}