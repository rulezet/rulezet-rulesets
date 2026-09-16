rule TTP_XOR_QUAD_CurrentVersionRun_68fd {
  strings:
    $key_68fd = { 3b 92 [2] 1f 9c [2] 34 b0 [2] 1a 92 [2] 0e 89 [2] 01 93 [2] 1f 8e [2] 1d 8f [2] 06 89 [2] 1a 8e [2] 06 a1 }

  condition:
    any of them
}