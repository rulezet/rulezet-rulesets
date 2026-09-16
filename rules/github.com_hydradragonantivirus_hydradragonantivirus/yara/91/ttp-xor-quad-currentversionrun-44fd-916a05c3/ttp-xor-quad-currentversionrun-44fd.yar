rule TTP_XOR_QUAD_CurrentVersionRun_44fd {
  strings:
    $key_44fd = { 17 92 [2] 33 9c [2] 18 b0 [2] 36 92 [2] 22 89 [2] 2d 93 [2] 33 8e [2] 31 8f [2] 2a 89 [2] 36 8e [2] 2a a1 }

  condition:
    any of them
}