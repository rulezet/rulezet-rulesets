rule TTP_XOR_QUAD_CurrentVersionRun_0b09 {
  strings:
    $key_0b09 = { 58 66 [2] 7c 68 [2] 57 44 [2] 79 66 [2] 6d 7d [2] 62 67 [2] 7c 7a [2] 7e 7b [2] 65 7d [2] 79 7a [2] 65 55 }

  condition:
    any of them
}