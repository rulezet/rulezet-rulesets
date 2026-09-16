rule TTP_XOR_QUAD_CurrentVersionRun_29f5 {
  strings:
    $key_29f5 = { 7a 9a [2] 5e 94 [2] 75 b8 [2] 5b 9a [2] 4f 81 [2] 40 9b [2] 5e 86 [2] 5c 87 [2] 47 81 [2] 5b 86 [2] 47 a9 }

  condition:
    any of them
}