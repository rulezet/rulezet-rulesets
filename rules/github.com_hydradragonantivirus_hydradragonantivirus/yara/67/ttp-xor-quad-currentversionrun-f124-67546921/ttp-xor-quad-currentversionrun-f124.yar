rule TTP_XOR_QUAD_CurrentVersionRun_f124 {
  strings:
    $key_f124 = { a2 4b [2] 86 45 [2] ad 69 [2] 83 4b [2] 97 50 [2] 98 4a [2] 86 57 [2] 84 56 [2] 9f 50 [2] 83 57 [2] 9f 78 }

  condition:
    any of them
}