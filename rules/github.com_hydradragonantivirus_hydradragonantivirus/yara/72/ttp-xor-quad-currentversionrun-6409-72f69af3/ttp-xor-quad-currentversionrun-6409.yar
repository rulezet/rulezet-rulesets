rule TTP_XOR_QUAD_CurrentVersionRun_6409 {
  strings:
    $key_6409 = { 37 66 [2] 13 68 [2] 38 44 [2] 16 66 [2] 02 7d [2] 0d 67 [2] 13 7a [2] 11 7b [2] 0a 7d [2] 16 7a [2] 0a 55 }

  condition:
    any of them
}