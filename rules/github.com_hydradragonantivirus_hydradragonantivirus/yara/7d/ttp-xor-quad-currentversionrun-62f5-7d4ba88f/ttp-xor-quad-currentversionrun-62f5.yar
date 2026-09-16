rule TTP_XOR_QUAD_CurrentVersionRun_62f5 {
  strings:
    $key_62f5 = { 31 9a [2] 15 94 [2] 3e b8 [2] 10 9a [2] 04 81 [2] 0b 9b [2] 15 86 [2] 17 87 [2] 0c 81 [2] 10 86 [2] 0c a9 }

  condition:
    any of them
}