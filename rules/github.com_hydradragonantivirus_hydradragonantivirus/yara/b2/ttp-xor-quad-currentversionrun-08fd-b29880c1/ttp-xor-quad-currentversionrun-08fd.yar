rule TTP_XOR_QUAD_CurrentVersionRun_08fd {
  strings:
    $key_08fd = { 5b 92 [2] 7f 9c [2] 54 b0 [2] 7a 92 [2] 6e 89 [2] 61 93 [2] 7f 8e [2] 7d 8f [2] 66 89 [2] 7a 8e [2] 66 a1 }

  condition:
    any of them
}