rule TTP_XOR_QUAD_CurrentVersionRun_f8f3 {
  strings:
    $key_f8f3 = { ab 9c [2] 8f 92 [2] a4 be [2] 8a 9c [2] 9e 87 [2] 91 9d [2] 8f 80 [2] 8d 81 [2] 96 87 [2] 8a 80 [2] 96 af }

  condition:
    any of them
}