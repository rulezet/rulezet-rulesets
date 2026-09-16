rule TTP_XOR_QUAD_CurrentVersionRun_1ff3 {
  strings:
    $key_1ff3 = { 4c 9c [2] 68 92 [2] 43 be [2] 6d 9c [2] 79 87 [2] 76 9d [2] 68 80 [2] 6a 81 [2] 71 87 [2] 6d 80 [2] 71 af }

  condition:
    any of them
}