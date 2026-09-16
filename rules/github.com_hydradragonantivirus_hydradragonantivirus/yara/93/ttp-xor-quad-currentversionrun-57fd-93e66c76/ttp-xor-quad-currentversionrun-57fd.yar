rule TTP_XOR_QUAD_CurrentVersionRun_57fd {
  strings:
    $key_57fd = { 04 92 [2] 20 9c [2] 0b b0 [2] 25 92 [2] 31 89 [2] 3e 93 [2] 20 8e [2] 22 8f [2] 39 89 [2] 25 8e [2] 39 a1 }

  condition:
    any of them
}