rule TTP_XOR_QUAD_CurrentVersionRun_1af3 {
  strings:
    $key_1af3 = { 49 9c [2] 6d 92 [2] 46 be [2] 68 9c [2] 7c 87 [2] 73 9d [2] 6d 80 [2] 6f 81 [2] 74 87 [2] 68 80 [2] 74 af }

  condition:
    any of them
}