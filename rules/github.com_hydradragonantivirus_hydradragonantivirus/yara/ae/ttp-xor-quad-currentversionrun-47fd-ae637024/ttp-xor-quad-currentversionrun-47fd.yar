rule TTP_XOR_QUAD_CurrentVersionRun_47fd {
  strings:
    $key_47fd = { 14 92 [2] 30 9c [2] 1b b0 [2] 35 92 [2] 21 89 [2] 2e 93 [2] 30 8e [2] 32 8f [2] 29 89 [2] 35 8e [2] 29 a1 }

  condition:
    any of them
}