rule TTP_XOR_QUAD_CurrentVersionRun_f207 {
  strings:
    $key_f207 = { a1 68 [2] 85 66 [2] ae 4a [2] 80 68 [2] 94 73 [2] 9b 69 [2] 85 74 [2] 87 75 [2] 9c 73 [2] 80 74 [2] 9c 5b }

  condition:
    any of them
}