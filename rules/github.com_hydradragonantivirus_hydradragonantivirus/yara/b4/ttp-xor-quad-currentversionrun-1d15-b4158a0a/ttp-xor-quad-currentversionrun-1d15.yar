rule TTP_XOR_QUAD_CurrentVersionRun_1d15 {
  strings:
    $key_1d15 = { 4e 7a [2] 6a 74 [2] 41 58 [2] 6f 7a [2] 7b 61 [2] 74 7b [2] 6a 66 [2] 68 67 [2] 73 61 [2] 6f 66 [2] 73 49 }

  condition:
    any of them
}