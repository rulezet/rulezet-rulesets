rule TTP_XOR_QUAD_CurrentVersionRun_6cf8 {
  strings:
    $key_6cf8 = { 3f 97 [2] 1b 99 [2] 30 b5 [2] 1e 97 [2] 0a 8c [2] 05 96 [2] 1b 8b [2] 19 8a [2] 02 8c [2] 1e 8b [2] 02 a4 }

  condition:
    any of them
}