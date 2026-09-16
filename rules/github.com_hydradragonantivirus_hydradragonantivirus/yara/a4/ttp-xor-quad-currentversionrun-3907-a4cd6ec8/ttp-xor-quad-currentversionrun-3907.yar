rule TTP_XOR_QUAD_CurrentVersionRun_3907 {
  strings:
    $key_3907 = { 6a 68 [2] 4e 66 [2] 65 4a [2] 4b 68 [2] 5f 73 [2] 50 69 [2] 4e 74 [2] 4c 75 [2] 57 73 [2] 4b 74 [2] 57 5b }

  condition:
    any of them
}