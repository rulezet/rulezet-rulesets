rule TTP_XOR_QUAD_CurrentVersionRun_26f5 {
  strings:
    $key_26f5 = { 75 9a [2] 51 94 [2] 7a b8 [2] 54 9a [2] 40 81 [2] 4f 9b [2] 51 86 [2] 53 87 [2] 48 81 [2] 54 86 [2] 48 a9 }

  condition:
    any of them
}