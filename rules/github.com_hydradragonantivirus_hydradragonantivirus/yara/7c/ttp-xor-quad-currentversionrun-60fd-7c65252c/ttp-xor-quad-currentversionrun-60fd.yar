rule TTP_XOR_QUAD_CurrentVersionRun_60fd {
  strings:
    $key_60fd = { 33 92 [2] 17 9c [2] 3c b0 [2] 12 92 [2] 06 89 [2] 09 93 [2] 17 8e [2] 15 8f [2] 0e 89 [2] 12 8e [2] 0e a1 }

  condition:
    any of them
}