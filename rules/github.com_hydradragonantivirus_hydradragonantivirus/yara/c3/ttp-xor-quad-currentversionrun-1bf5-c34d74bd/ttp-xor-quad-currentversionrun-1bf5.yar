rule TTP_XOR_QUAD_CurrentVersionRun_1bf5 {
  strings:
    $key_1bf5 = { 48 9a [2] 6c 94 [2] 47 b8 [2] 69 9a [2] 7d 81 [2] 72 9b [2] 6c 86 [2] 6e 87 [2] 75 81 [2] 69 86 [2] 75 a9 }

  condition:
    any of them
}