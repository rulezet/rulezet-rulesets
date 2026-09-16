rule TTP_XOR_QUAD_CurrentVersionRun_f85a {
  strings:
    $key_f85a = { ab 35 [2] 8f 3b [2] a4 17 [2] 8a 35 [2] 9e 2e [2] 91 34 [2] 8f 29 [2] 8d 28 [2] 96 2e [2] 8a 29 [2] 96 06 }

  condition:
    any of them
}