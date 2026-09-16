rule TTP_XOR_QUAD_CurrentVersionRun_0625 {
  strings:
    $key_0625 = { 55 4a [2] 71 44 [2] 5a 68 [2] 74 4a [2] 60 51 [2] 6f 4b [2] 71 56 [2] 73 57 [2] 68 51 [2] 74 56 [2] 68 79 }

  condition:
    any of them
}