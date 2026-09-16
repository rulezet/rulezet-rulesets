rule TTP_XOR_QUAD_CurrentVersionRun_4df9 {
  strings:
    $key_4df9 = { 1e 96 [2] 3a 98 [2] 11 b4 [2] 3f 96 [2] 2b 8d [2] 24 97 [2] 3a 8a [2] 38 8b [2] 23 8d [2] 3f 8a [2] 23 a5 }

  condition:
    any of them
}