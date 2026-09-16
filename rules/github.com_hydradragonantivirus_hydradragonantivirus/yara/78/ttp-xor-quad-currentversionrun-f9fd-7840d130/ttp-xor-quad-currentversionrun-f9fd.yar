rule TTP_XOR_QUAD_CurrentVersionRun_f9fd {
  strings:
    $key_f9fd = { aa 92 [2] 8e 9c [2] a5 b0 [2] 8b 92 [2] 9f 89 [2] 90 93 [2] 8e 8e [2] 8c 8f [2] 97 89 [2] 8b 8e [2] 97 a1 }

  condition:
    any of them
}