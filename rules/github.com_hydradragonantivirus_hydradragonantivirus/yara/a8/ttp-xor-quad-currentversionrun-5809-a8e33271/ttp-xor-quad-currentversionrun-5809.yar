rule TTP_XOR_QUAD_CurrentVersionRun_5809 {
  strings:
    $key_5809 = { 0b 66 [2] 2f 68 [2] 04 44 [2] 2a 66 [2] 3e 7d [2] 31 67 [2] 2f 7a [2] 2d 7b [2] 36 7d [2] 2a 7a [2] 36 55 }

  condition:
    any of them
}