rule TTP_XOR_QUAD_CurrentVersionRun_fa5a {
  strings:
    $key_fa5a = { a9 35 [2] 8d 3b [2] a6 17 [2] 88 35 [2] 9c 2e [2] 93 34 [2] 8d 29 [2] 8f 28 [2] 94 2e [2] 88 29 [2] 94 06 }

  condition:
    any of them
}