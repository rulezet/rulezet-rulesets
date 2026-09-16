rule TTP_XOR_QUAD_CurrentVersionRun_5874 {
  strings:
    $key_5874 = { 0b 1b [2] 2f 15 [2] 04 39 [2] 2a 1b [2] 3e 00 [2] 31 1a [2] 2f 07 [2] 2d 06 [2] 36 00 [2] 2a 07 [2] 36 28 }

  condition:
    any of them
}