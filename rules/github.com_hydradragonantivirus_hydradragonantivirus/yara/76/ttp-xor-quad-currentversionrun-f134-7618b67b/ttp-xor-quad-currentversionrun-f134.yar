rule TTP_XOR_QUAD_CurrentVersionRun_f134 {
  strings:
    $key_f134 = { a2 5b [2] 86 55 [2] ad 79 [2] 83 5b [2] 97 40 [2] 98 5a [2] 86 47 [2] 84 46 [2] 9f 40 [2] 83 47 [2] 9f 68 }

  condition:
    any of them
}