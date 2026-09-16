rule TTP_XOR_QUAD_CurrentVersionRun_6cf9 {
  strings:
    $key_6cf9 = { 3f 96 [2] 1b 98 [2] 30 b4 [2] 1e 96 [2] 0a 8d [2] 05 97 [2] 1b 8a [2] 19 8b [2] 02 8d [2] 1e 8a [2] 02 a5 }

  condition:
    any of them
}