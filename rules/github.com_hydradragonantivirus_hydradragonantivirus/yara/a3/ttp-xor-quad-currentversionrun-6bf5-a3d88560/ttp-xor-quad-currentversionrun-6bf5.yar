rule TTP_XOR_QUAD_CurrentVersionRun_6bf5 {
  strings:
    $key_6bf5 = { 38 9a [2] 1c 94 [2] 37 b8 [2] 19 9a [2] 0d 81 [2] 02 9b [2] 1c 86 [2] 1e 87 [2] 05 81 [2] 19 86 [2] 05 a9 }

  condition:
    any of them
}