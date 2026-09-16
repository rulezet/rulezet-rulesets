rule TTP_XOR_QUAD_CurrentVersionRun_f17a {
  strings:
    $key_f17a = { a2 15 [2] 86 1b [2] ad 37 [2] 83 15 [2] 97 0e [2] 98 14 [2] 86 09 [2] 84 08 [2] 9f 0e [2] 83 09 [2] 9f 26 }

  condition:
    any of them
}