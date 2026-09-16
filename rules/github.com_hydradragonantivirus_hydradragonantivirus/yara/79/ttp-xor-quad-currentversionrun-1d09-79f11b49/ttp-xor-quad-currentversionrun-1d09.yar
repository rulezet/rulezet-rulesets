rule TTP_XOR_QUAD_CurrentVersionRun_1d09 {
  strings:
    $key_1d09 = { 4e 66 [2] 6a 68 [2] 41 44 [2] 6f 66 [2] 7b 7d [2] 74 67 [2] 6a 7a [2] 68 7b [2] 73 7d [2] 6f 7a [2] 73 55 }

  condition:
    any of them
}