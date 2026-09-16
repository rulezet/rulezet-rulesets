rule TTP_XOR_QUAD_CurrentVersionRun_5573 {
  strings:
    $key_5573 = { 06 1c [2] 22 12 [2] 09 3e [2] 27 1c [2] 33 07 [2] 3c 1d [2] 22 00 [2] 20 01 [2] 3b 07 [2] 27 00 [2] 3b 2f }

  condition:
    any of them
}