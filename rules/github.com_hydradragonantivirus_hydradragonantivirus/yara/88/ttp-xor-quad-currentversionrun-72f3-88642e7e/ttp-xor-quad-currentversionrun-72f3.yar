rule TTP_XOR_QUAD_CurrentVersionRun_72f3 {
  strings:
    $key_72f3 = { 21 9c [2] 05 92 [2] 2e be [2] 00 9c [2] 14 87 [2] 1b 9d [2] 05 80 [2] 07 81 [2] 1c 87 [2] 00 80 [2] 1c af }

  condition:
    any of them
}