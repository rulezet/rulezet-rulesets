rule TTP_XOR_QUAD_CurrentVersionRun_40fd {
  strings:
    $key_40fd = { 13 92 [2] 37 9c [2] 1c b0 [2] 32 92 [2] 26 89 [2] 29 93 [2] 37 8e [2] 35 8f [2] 2e 89 [2] 32 8e [2] 2e a1 }

  condition:
    any of them
}