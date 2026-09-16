rule TTP_XOR_QUAD_CurrentVersionRun_70fd {
  strings:
    $key_70fd = { 23 92 [2] 07 9c [2] 2c b0 [2] 02 92 [2] 16 89 [2] 19 93 [2] 07 8e [2] 05 8f [2] 1e 89 [2] 02 8e [2] 1e a1 }

  condition:
    any of them
}