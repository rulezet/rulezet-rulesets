rule TTP_XOR_QUAD_CurrentVersionRun_08f3 {
  strings:
    $key_08f3 = { 5b 9c [2] 7f 92 [2] 54 be [2] 7a 9c [2] 6e 87 [2] 61 9d [2] 7f 80 [2] 7d 81 [2] 66 87 [2] 7a 80 [2] 66 af }

  condition:
    any of them
}