rule TTP_XOR_QUAD_CurrentVersionRun_5007 {
  strings:
    $key_5007 = { 03 68 [2] 27 66 [2] 0c 4a [2] 22 68 [2] 36 73 [2] 39 69 [2] 27 74 [2] 25 75 [2] 3e 73 [2] 22 74 [2] 3e 5b }

  condition:
    any of them
}