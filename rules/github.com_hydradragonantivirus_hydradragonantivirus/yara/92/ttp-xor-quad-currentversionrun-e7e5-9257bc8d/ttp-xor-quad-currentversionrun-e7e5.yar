rule TTP_XOR_QUAD_CurrentVersionRun_e7e5 {
  strings:
    $key_e7e5 = { b4 8a [2] 90 84 [2] bb a8 [2] 95 8a [2] 81 91 [2] 8e 8b [2] 90 96 [2] 92 97 [2] 89 91 [2] 95 96 [2] 89 b9 }

  condition:
    any of them
}