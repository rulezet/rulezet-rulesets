rule TTP_XOR_QUAD_CurrentVersionRun_6609 {
  strings:
    $key_6609 = { 35 66 [2] 11 68 [2] 3a 44 [2] 14 66 [2] 00 7d [2] 0f 67 [2] 11 7a [2] 13 7b [2] 08 7d [2] 14 7a [2] 08 55 }

  condition:
    any of them
}