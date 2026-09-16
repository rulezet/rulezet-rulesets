rule TTP_XOR_QUAD_CurrentVersionRun_0409 {
  strings:
    $key_0409 = { 57 66 [2] 73 68 [2] 58 44 [2] 76 66 [2] 62 7d [2] 6d 67 [2] 73 7a [2] 71 7b [2] 6a 7d [2] 76 7a [2] 6a 55 }

  condition:
    any of them
}