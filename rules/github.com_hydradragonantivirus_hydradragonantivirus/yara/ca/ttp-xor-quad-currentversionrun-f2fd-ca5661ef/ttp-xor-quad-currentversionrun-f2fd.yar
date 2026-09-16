rule TTP_XOR_QUAD_CurrentVersionRun_f2fd {
  strings:
    $key_f2fd = { a1 92 [2] 85 9c [2] ae b0 [2] 80 92 [2] 94 89 [2] 9b 93 [2] 85 8e [2] 87 8f [2] 9c 89 [2] 80 8e [2] 9c a1 }

  condition:
    any of them
}