rule TTP_XOR_QUAD_CurrentVersionRun_19f5 {
  strings:
    $key_19f5 = { 4a 9a [2] 6e 94 [2] 45 b8 [2] 6b 9a [2] 7f 81 [2] 70 9b [2] 6e 86 [2] 6c 87 [2] 77 81 [2] 6b 86 [2] 77 a9 }

  condition:
    any of them
}