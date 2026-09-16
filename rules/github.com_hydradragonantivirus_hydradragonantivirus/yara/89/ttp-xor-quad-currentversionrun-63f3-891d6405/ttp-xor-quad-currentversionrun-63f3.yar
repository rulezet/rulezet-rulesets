rule TTP_XOR_QUAD_CurrentVersionRun_63f3 {
  strings:
    $key_63f3 = { 30 9c [2] 14 92 [2] 3f be [2] 11 9c [2] 05 87 [2] 0a 9d [2] 14 80 [2] 16 81 [2] 0d 87 [2] 11 80 [2] 0d af }

  condition:
    any of them
}