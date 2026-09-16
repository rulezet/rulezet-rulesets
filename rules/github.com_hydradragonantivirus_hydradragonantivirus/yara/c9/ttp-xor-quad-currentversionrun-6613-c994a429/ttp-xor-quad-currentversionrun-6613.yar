rule TTP_XOR_QUAD_CurrentVersionRun_6613 {
  strings:
    $key_6613 = { 35 7c [2] 11 72 [2] 3a 5e [2] 14 7c [2] 00 67 [2] 0f 7d [2] 11 60 [2] 13 61 [2] 08 67 [2] 14 60 [2] 08 4f }

  condition:
    any of them
}