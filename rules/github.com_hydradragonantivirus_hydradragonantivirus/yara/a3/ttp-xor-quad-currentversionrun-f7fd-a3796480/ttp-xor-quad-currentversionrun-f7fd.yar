rule TTP_XOR_QUAD_CurrentVersionRun_f7fd {
  strings:
    $key_f7fd = { a4 92 [2] 80 9c [2] ab b0 [2] 85 92 [2] 91 89 [2] 9e 93 [2] 80 8e [2] 82 8f [2] 99 89 [2] 85 8e [2] 99 a1 }

  condition:
    any of them
}