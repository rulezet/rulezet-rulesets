rule TTP_XOR_QUAD_CurrentVersionRun_f11a {
  strings:
    $key_f11a = { a2 75 [2] 86 7b [2] ad 57 [2] 83 75 [2] 97 6e [2] 98 74 [2] 86 69 [2] 84 68 [2] 9f 6e [2] 83 69 [2] 9f 46 }

  condition:
    any of them
}