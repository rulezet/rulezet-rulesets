rule TTP_XOR_QUAD_CurrentVersionRun_e7e4 {
  strings:
    $key_e7e4 = { b4 8b [2] 90 85 [2] bb a9 [2] 95 8b [2] 81 90 [2] 8e 8a [2] 90 97 [2] 92 96 [2] 89 90 [2] 95 97 [2] 89 b8 }

  condition:
    any of them
}