rule TTP_XOR_QUAD_CurrentVersionRun_f133 {
  strings:
    $key_f133 = { a2 5c [2] 86 52 [2] ad 7e [2] 83 5c [2] 97 47 [2] 98 5d [2] 86 40 [2] 84 41 [2] 9f 47 [2] 83 40 [2] 9f 6f }

  condition:
    any of them
}