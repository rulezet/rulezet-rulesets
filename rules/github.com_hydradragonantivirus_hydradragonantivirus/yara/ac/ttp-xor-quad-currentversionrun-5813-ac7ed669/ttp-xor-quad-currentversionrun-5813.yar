rule TTP_XOR_QUAD_CurrentVersionRun_5813 {
  strings:
    $key_5813 = { 0b 7c [2] 2f 72 [2] 04 5e [2] 2a 7c [2] 3e 67 [2] 31 7d [2] 2f 60 [2] 2d 61 [2] 36 67 [2] 2a 60 [2] 36 4f }

  condition:
    any of them
}