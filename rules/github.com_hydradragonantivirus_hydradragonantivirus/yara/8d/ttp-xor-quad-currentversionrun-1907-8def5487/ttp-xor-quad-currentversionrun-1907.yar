rule TTP_XOR_QUAD_CurrentVersionRun_1907 {
  strings:
    $key_1907 = { 4a 68 [2] 6e 66 [2] 45 4a [2] 6b 68 [2] 7f 73 [2] 70 69 [2] 6e 74 [2] 6c 75 [2] 77 73 [2] 6b 74 [2] 77 5b }

  condition:
    any of them
}