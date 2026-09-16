rule TTP_XOR_QUAD_CurrentVersionRun_f6fd {
  strings:
    $key_f6fd = { a5 92 [2] 81 9c [2] aa b0 [2] 84 92 [2] 90 89 [2] 9f 93 [2] 81 8e [2] 83 8f [2] 98 89 [2] 84 8e [2] 98 a1 }

  condition:
    any of them
}