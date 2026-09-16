rule TTP_XOR_QUAD_CurrentVersionRun_e803 {
  strings:
    $key_e803 = { bb 6c [2] 9f 62 [2] b4 4e [2] 9a 6c [2] 8e 77 [2] 81 6d [2] 9f 70 [2] 9d 71 [2] 86 77 [2] 9a 70 [2] 86 5f }

  condition:
    any of them
}