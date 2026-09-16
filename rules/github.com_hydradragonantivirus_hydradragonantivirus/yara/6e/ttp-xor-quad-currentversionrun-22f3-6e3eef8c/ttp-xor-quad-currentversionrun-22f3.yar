rule TTP_XOR_QUAD_CurrentVersionRun_22f3 {
  strings:
    $key_22f3 = { 71 9c [2] 55 92 [2] 7e be [2] 50 9c [2] 44 87 [2] 4b 9d [2] 55 80 [2] 57 81 [2] 4c 87 [2] 50 80 [2] 4c af }

  condition:
    any of them
}