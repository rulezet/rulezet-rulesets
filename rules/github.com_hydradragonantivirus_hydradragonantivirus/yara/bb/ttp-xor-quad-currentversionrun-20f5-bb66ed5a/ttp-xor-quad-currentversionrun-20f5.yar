rule TTP_XOR_QUAD_CurrentVersionRun_20f5 {
  strings:
    $key_20f5 = { 73 9a [2] 57 94 [2] 7c b8 [2] 52 9a [2] 46 81 [2] 49 9b [2] 57 86 [2] 55 87 [2] 4e 81 [2] 52 86 [2] 4e a9 }

  condition:
    any of them
}