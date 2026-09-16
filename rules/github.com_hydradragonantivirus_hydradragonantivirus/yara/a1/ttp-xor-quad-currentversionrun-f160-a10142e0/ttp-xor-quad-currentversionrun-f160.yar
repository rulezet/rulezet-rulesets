rule TTP_XOR_QUAD_CurrentVersionRun_f160 {
  strings:
    $key_f160 = { a2 0f [2] 86 01 [2] ad 2d [2] 83 0f [2] 97 14 [2] 98 0e [2] 86 13 [2] 84 12 [2] 9f 14 [2] 83 13 [2] 9f 3c }

  condition:
    any of them
}