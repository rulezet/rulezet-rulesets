rule TTP_XOR_QUAD_CurrentVersionRun_67fd {
  strings:
    $key_67fd = { 34 92 [2] 10 9c [2] 3b b0 [2] 15 92 [2] 01 89 [2] 0e 93 [2] 10 8e [2] 12 8f [2] 09 89 [2] 15 8e [2] 09 a1 }

  condition:
    any of them
}