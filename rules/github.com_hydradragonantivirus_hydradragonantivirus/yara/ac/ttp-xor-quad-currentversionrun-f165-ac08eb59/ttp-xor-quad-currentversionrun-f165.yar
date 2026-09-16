rule TTP_XOR_QUAD_CurrentVersionRun_f165 {
  strings:
    $key_f165 = { a2 0a [2] 86 04 [2] ad 28 [2] 83 0a [2] 97 11 [2] 98 0b [2] 86 16 [2] 84 17 [2] 9f 11 [2] 83 16 [2] 9f 39 }

  condition:
    any of them
}