rule TTP_XOR_QUAD_CurrentVersionRun_5707 {
  strings:
    $key_5707 = { 04 68 [2] 20 66 [2] 0b 4a [2] 25 68 [2] 31 73 [2] 3e 69 [2] 20 74 [2] 22 75 [2] 39 73 [2] 25 74 [2] 39 5b }

  condition:
    any of them
}