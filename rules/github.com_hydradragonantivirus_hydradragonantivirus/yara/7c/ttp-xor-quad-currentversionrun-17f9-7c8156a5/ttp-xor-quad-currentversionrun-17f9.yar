rule TTP_XOR_QUAD_CurrentVersionRun_17f9 {
  strings:
    $key_17f9 = { 44 96 [2] 60 98 [2] 4b b4 [2] 65 96 [2] 71 8d [2] 7e 97 [2] 60 8a [2] 62 8b [2] 79 8d [2] 65 8a [2] 79 a5 }

  condition:
    any of them
}