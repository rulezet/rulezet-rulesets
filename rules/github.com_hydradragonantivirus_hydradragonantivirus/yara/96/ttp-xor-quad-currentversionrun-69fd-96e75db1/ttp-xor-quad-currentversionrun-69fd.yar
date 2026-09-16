rule TTP_XOR_QUAD_CurrentVersionRun_69fd {
  strings:
    $key_69fd = { 3a 92 [2] 1e 9c [2] 35 b0 [2] 1b 92 [2] 0f 89 [2] 00 93 [2] 1e 8e [2] 1c 8f [2] 07 89 [2] 1b 8e [2] 07 a1 }

  condition:
    any of them
}