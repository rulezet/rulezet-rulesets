rule TTP_XOR_QUAD_CurrentVersionRun_09f3 {
  strings:
    $key_09f3 = { 5a 9c [2] 7e 92 [2] 55 be [2] 7b 9c [2] 6f 87 [2] 60 9d [2] 7e 80 [2] 7c 81 [2] 67 87 [2] 7b 80 [2] 67 af }

  condition:
    any of them
}