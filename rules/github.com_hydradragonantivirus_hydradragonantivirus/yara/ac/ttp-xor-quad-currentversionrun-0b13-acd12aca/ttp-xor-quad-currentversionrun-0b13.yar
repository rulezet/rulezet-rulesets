rule TTP_XOR_QUAD_CurrentVersionRun_0b13 {
  strings:
    $key_0b13 = { 58 7c [2] 7c 72 [2] 57 5e [2] 79 7c [2] 6d 67 [2] 62 7d [2] 7c 60 [2] 7e 61 [2] 65 67 [2] 79 60 [2] 65 4f }

  condition:
    any of them
}