rule TTP_XOR_QUAD_CurrentVersionRun_e8f3 {
  strings:
    $key_e8f3 = { bb 9c [2] 9f 92 [2] b4 be [2] 9a 9c [2] 8e 87 [2] 81 9d [2] 9f 80 [2] 9d 81 [2] 86 87 [2] 9a 80 [2] 86 af }

  condition:
    any of them
}