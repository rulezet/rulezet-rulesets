rule TTP_XOR_QUAD_CurrentVersionRun_f31a {
  strings:
    $key_f31a = { a0 75 [2] 84 7b [2] af 57 [2] 81 75 [2] 95 6e [2] 9a 74 [2] 84 69 [2] 86 68 [2] 9d 6e [2] 81 69 [2] 9d 46 }

  condition:
    any of them
}