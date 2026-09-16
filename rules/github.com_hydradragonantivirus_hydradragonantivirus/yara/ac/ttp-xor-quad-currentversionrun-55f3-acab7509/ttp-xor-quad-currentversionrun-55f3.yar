rule TTP_XOR_QUAD_CurrentVersionRun_55f3 {
  strings:
    $key_55f3 = { 06 9c [2] 22 92 [2] 09 be [2] 27 9c [2] 33 87 [2] 3c 9d [2] 22 80 [2] 20 81 [2] 3b 87 [2] 27 80 [2] 3b af }

  condition:
    any of them
}