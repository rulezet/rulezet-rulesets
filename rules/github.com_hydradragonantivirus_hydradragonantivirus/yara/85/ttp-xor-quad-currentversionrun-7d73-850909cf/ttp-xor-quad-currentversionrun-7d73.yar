rule TTP_XOR_QUAD_CurrentVersionRun_7d73 {
  strings:
    $key_7d73 = { 2e 1c [2] 0a 12 [2] 21 3e [2] 0f 1c [2] 1b 07 [2] 14 1d [2] 0a 00 [2] 08 01 [2] 13 07 [2] 0f 00 [2] 13 2f }

  condition:
    any of them
}