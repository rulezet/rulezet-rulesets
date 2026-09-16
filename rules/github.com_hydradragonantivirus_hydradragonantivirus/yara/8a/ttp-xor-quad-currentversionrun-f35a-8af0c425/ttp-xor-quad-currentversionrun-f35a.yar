rule TTP_XOR_QUAD_CurrentVersionRun_f35a {
  strings:
    $key_f35a = { a0 35 [2] 84 3b [2] af 17 [2] 81 35 [2] 95 2e [2] 9a 34 [2] 84 29 [2] 86 28 [2] 9d 2e [2] 81 29 [2] 9d 06 }

  condition:
    any of them
}