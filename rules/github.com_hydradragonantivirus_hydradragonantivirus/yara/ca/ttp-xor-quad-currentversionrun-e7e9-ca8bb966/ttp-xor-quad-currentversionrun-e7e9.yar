rule TTP_XOR_QUAD_CurrentVersionRun_e7e9 {
  strings:
    $key_e7e9 = { b4 86 [2] 90 88 [2] bb a4 [2] 95 86 [2] 81 9d [2] 8e 87 [2] 90 9a [2] 92 9b [2] 89 9d [2] 95 9a [2] 89 b5 }

  condition:
    any of them
}