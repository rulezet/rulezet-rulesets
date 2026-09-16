rule TTP_XOR_QUAD_CurrentVersionRun_6573 {
  strings:
    $key_6573 = { 36 1c [2] 12 12 [2] 39 3e [2] 17 1c [2] 03 07 [2] 0c 1d [2] 12 00 [2] 10 01 [2] 0b 07 [2] 17 00 [2] 0b 2f }

  condition:
    any of them
}