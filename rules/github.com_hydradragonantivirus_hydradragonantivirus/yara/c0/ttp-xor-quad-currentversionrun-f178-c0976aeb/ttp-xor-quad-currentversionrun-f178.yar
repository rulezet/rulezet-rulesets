rule TTP_XOR_QUAD_CurrentVersionRun_f178 {
  strings:
    $key_f178 = { a2 17 [2] 86 19 [2] ad 35 [2] 83 17 [2] 97 0c [2] 98 16 [2] 86 0b [2] 84 0a [2] 9f 0c [2] 83 0b [2] 9f 24 }

  condition:
    any of them
}