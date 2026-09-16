rule TTP_XOR_QUAD_CurrentVersionRun_f163 {
  strings:
    $key_f163 = { a2 0c [2] 86 02 [2] ad 2e [2] 83 0c [2] 97 17 [2] 98 0d [2] 86 10 [2] 84 11 [2] 9f 17 [2] 83 10 [2] 9f 3f }

  condition:
    any of them
}