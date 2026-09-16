rule TTP_XOR_QUAD_CurrentVersionRun_f119 {
  strings:
    $key_f119 = { a2 76 [2] 86 78 [2] ad 54 [2] 83 76 [2] 97 6d [2] 98 77 [2] 86 6a [2] 84 6b [2] 9f 6d [2] 83 6a [2] 9f 45 }

  condition:
    any of them
}