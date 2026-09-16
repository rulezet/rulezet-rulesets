rule TTP_XOR_QUAD_CurrentVersionRun_32f3 {
  strings:
    $key_32f3 = { 61 9c [2] 45 92 [2] 6e be [2] 40 9c [2] 54 87 [2] 5b 9d [2] 45 80 [2] 47 81 [2] 5c 87 [2] 40 80 [2] 5c af }

  condition:
    any of them
}