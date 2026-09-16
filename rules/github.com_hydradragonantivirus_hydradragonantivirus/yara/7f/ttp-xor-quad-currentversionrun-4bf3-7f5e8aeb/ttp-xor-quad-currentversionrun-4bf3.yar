rule TTP_XOR_QUAD_CurrentVersionRun_4bf3 {
  strings:
    $key_4bf3 = { 18 9c [2] 3c 92 [2] 17 be [2] 39 9c [2] 2d 87 [2] 22 9d [2] 3c 80 [2] 3e 81 [2] 25 87 [2] 39 80 [2] 25 af }

  condition:
    any of them
}