rule TTP_XOR_QUAD_CurrentVersionRun_35f5 {
  strings:
    $key_35f5 = { 66 9a [2] 42 94 [2] 69 b8 [2] 47 9a [2] 53 81 [2] 5c 9b [2] 42 86 [2] 40 87 [2] 5b 81 [2] 47 86 [2] 5b a9 }

  condition:
    any of them
}