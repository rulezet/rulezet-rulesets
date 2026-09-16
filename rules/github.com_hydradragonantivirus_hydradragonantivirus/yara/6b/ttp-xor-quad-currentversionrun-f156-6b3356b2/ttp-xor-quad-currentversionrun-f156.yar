rule TTP_XOR_QUAD_CurrentVersionRun_f156 {
  strings:
    $key_f156 = { a2 39 [2] 86 37 [2] ad 1b [2] 83 39 [2] 97 22 [2] 98 38 [2] 86 25 [2] 84 24 [2] 9f 22 [2] 83 25 [2] 9f 0a }

  condition:
    any of them
}