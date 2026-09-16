rule TTP_XOR_QUAD_CurrentVersionRun_6009 {
  strings:
    $key_6009 = { 33 66 [2] 17 68 [2] 3c 44 [2] 12 66 [2] 06 7d [2] 09 67 [2] 17 7a [2] 15 7b [2] 0e 7d [2] 12 7a [2] 0e 55 }

  condition:
    any of them
}