rule TTP_XOR_QUAD_CurrentVersionRun_27fd {
  strings:
    $key_27fd = { 74 92 [2] 50 9c [2] 7b b0 [2] 55 92 [2] 41 89 [2] 4e 93 [2] 50 8e [2] 52 8f [2] 49 89 [2] 55 8e [2] 49 a1 }

  condition:
    any of them
}