rule TTP_XOR_QUAD_CurrentVersionRun_e65a {
  strings:
    $key_e65a = { b5 35 [2] 91 3b [2] ba 17 [2] 94 35 [2] 80 2e [2] 8f 34 [2] 91 29 [2] 93 28 [2] 88 2e [2] 94 29 [2] 88 06 }

  condition:
    any of them
}