rule TTP_XOR_QUAD_CurrentVersionRun_0b03 {
  strings:
    $key_0b03 = { 58 6c [2] 7c 62 [2] 57 4e [2] 79 6c [2] 6d 77 [2] 62 6d [2] 7c 70 [2] 7e 71 [2] 65 77 [2] 79 70 [2] 65 5f }

  condition:
    any of them
}