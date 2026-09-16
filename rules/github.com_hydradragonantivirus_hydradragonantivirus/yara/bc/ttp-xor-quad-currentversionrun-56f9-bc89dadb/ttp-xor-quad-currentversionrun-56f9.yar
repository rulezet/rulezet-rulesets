rule TTP_XOR_QUAD_CurrentVersionRun_56f9 {
  strings:
    $key_56f9 = { 05 96 [2] 21 98 [2] 0a b4 [2] 24 96 [2] 30 8d [2] 3f 97 [2] 21 8a [2] 23 8b [2] 38 8d [2] 24 8a [2] 38 a5 }

  condition:
    any of them
}