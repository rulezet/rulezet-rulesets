rule TTP_XOR_QUAD_CurrentVersionRun_f157 {
  strings:
    $key_f157 = { a2 38 [2] 86 36 [2] ad 1a [2] 83 38 [2] 97 23 [2] 98 39 [2] 86 24 [2] 84 25 [2] 9f 23 [2] 83 24 [2] 9f 0b }

  condition:
    any of them
}