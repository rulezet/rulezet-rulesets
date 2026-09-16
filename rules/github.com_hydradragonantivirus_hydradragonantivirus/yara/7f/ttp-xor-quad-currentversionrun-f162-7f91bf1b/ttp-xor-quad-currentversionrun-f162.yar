rule TTP_XOR_QUAD_CurrentVersionRun_f162 {
  strings:
    $key_f162 = { a2 0d [2] 86 03 [2] ad 2f [2] 83 0d [2] 97 16 [2] 98 0c [2] 86 11 [2] 84 10 [2] 9f 16 [2] 83 11 [2] 9f 3e }

  condition:
    any of them
}