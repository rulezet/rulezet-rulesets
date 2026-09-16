rule TTP_XOR_QUAD_CurrentVersionRun_6207 {
  strings:
    $key_6207 = { 31 68 [2] 15 66 [2] 3e 4a [2] 10 68 [2] 04 73 [2] 0b 69 [2] 15 74 [2] 17 75 [2] 0c 73 [2] 10 74 [2] 0c 5b }

  condition:
    any of them
}