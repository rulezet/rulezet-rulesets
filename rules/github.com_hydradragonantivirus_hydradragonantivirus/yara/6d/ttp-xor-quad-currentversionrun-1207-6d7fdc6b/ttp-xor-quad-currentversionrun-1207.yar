rule TTP_XOR_QUAD_CurrentVersionRun_1207 {
  strings:
    $key_1207 = { 41 68 [2] 65 66 [2] 4e 4a [2] 60 68 [2] 74 73 [2] 7b 69 [2] 65 74 [2] 67 75 [2] 7c 73 [2] 60 74 [2] 7c 5b }

  condition:
    any of them
}