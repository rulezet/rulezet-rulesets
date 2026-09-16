rule TTP_XOR_QUAD_CurrentVersionRun_2ff3 {
  strings:
    $key_2ff3 = { 7c 9c [2] 58 92 [2] 73 be [2] 5d 9c [2] 49 87 [2] 46 9d [2] 58 80 [2] 5a 81 [2] 41 87 [2] 5d 80 [2] 41 af }

  condition:
    any of them
}