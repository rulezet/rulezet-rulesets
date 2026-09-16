rule TTP_XOR_QUAD_CurrentVersionRun_77fd {
  strings:
    $key_77fd = { 24 92 [2] 00 9c [2] 2b b0 [2] 05 92 [2] 11 89 [2] 1e 93 [2] 00 8e [2] 02 8f [2] 19 89 [2] 05 8e [2] 19 a1 }

  condition:
    any of them
}