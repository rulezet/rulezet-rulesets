rule TTP_XOR_QUAD_CurrentVersionRun_f5fd {
  strings:
    $key_f5fd = { a6 92 [2] 82 9c [2] a9 b0 [2] 87 92 [2] 93 89 [2] 9c 93 [2] 82 8e [2] 80 8f [2] 9b 89 [2] 87 8e [2] 9b a1 }

  condition:
    any of them
}