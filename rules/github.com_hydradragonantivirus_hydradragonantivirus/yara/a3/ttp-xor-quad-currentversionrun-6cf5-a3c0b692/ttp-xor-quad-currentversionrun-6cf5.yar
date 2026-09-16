rule TTP_XOR_QUAD_CurrentVersionRun_6cf5 {
  strings:
    $key_6cf5 = { 3f 9a [2] 1b 94 [2] 30 b8 [2] 1e 9a [2] 0a 81 [2] 05 9b [2] 1b 86 [2] 19 87 [2] 02 81 [2] 1e 86 [2] 02 a9 }

  condition:
    any of them
}