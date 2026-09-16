rule TTP_XOR_QUAD_CurrentVersionRun_17f8 {
  strings:
    $key_17f8 = { 44 97 [2] 60 99 [2] 4b b5 [2] 65 97 [2] 71 8c [2] 7e 96 [2] 60 8b [2] 62 8a [2] 79 8c [2] 65 8b [2] 79 a4 }

  condition:
    any of them
}