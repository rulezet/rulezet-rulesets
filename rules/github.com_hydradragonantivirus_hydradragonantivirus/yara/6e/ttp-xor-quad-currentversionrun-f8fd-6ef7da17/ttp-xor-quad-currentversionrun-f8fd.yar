rule TTP_XOR_QUAD_CurrentVersionRun_f8fd {
  strings:
    $key_f8fd = { ab 92 [2] 8f 9c [2] a4 b0 [2] 8a 92 [2] 9e 89 [2] 91 93 [2] 8f 8e [2] 8d 8f [2] 96 89 [2] 8a 8e [2] 96 a1 }

  condition:
    any of them
}