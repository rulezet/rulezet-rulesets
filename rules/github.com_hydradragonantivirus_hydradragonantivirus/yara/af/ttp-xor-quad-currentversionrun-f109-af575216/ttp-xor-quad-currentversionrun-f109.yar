rule TTP_XOR_QUAD_CurrentVersionRun_f109 {
  strings:
    $key_f109 = { a2 66 [2] 86 68 [2] ad 44 [2] 83 66 [2] 97 7d [2] 98 67 [2] 86 7a [2] 84 7b [2] 9f 7d [2] 83 7a [2] 9f 55 }

  condition:
    any of them
}