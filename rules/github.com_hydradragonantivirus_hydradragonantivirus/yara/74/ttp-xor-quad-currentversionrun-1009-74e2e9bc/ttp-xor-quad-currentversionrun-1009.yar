rule TTP_XOR_QUAD_CurrentVersionRun_1009 {
  strings:
    $key_1009 = { 43 66 [2] 67 68 [2] 4c 44 [2] 62 66 [2] 76 7d [2] 79 67 [2] 67 7a [2] 65 7b [2] 7e 7d [2] 62 7a [2] 7e 55 }

  condition:
    any of them
}