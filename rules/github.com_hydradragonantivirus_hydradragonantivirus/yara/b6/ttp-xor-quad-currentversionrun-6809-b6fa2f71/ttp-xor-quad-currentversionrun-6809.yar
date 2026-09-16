rule TTP_XOR_QUAD_CurrentVersionRun_6809 {
  strings:
    $key_6809 = { 3b 66 [2] 1f 68 [2] 34 44 [2] 1a 66 [2] 0e 7d [2] 01 67 [2] 1f 7a [2] 1d 7b [2] 06 7d [2] 1a 7a [2] 06 55 }

  condition:
    any of them
}