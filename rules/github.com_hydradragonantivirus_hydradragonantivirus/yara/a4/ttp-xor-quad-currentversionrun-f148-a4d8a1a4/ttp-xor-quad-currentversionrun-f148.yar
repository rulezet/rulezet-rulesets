rule TTP_XOR_QUAD_CurrentVersionRun_f148 {
  strings:
    $key_f148 = { a2 27 [2] 86 29 [2] ad 05 [2] 83 27 [2] 97 3c [2] 98 26 [2] 86 3b [2] 84 3a [2] 9f 3c [2] 83 3b [2] 9f 14 }

  condition:
    any of them
}