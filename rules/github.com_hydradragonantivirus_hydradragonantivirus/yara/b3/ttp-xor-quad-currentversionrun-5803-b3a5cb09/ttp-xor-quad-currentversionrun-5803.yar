rule TTP_XOR_QUAD_CurrentVersionRun_5803 {
  strings:
    $key_5803 = { 0b 6c [2] 2f 62 [2] 04 4e [2] 2a 6c [2] 3e 77 [2] 31 6d [2] 2f 70 [2] 2d 71 [2] 36 77 [2] 2a 70 [2] 36 5f }

  condition:
    any of them
}