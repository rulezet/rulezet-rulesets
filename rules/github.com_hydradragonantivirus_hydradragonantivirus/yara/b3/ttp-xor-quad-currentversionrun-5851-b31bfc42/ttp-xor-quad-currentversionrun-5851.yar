rule TTP_XOR_QUAD_CurrentVersionRun_5851 {
  strings:
    $key_5851 = { 0b 3e [2] 2f 30 [2] 04 1c [2] 2a 3e [2] 3e 25 [2] 31 3f [2] 2f 22 [2] 2d 23 [2] 36 25 [2] 2a 22 [2] 36 0d }

  condition:
    any of them
}