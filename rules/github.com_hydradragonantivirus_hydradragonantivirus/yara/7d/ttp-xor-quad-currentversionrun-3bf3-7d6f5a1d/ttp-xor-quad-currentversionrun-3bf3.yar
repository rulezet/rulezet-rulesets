rule TTP_XOR_QUAD_CurrentVersionRun_3bf3 {
  strings:
    $key_3bf3 = { 68 9c [2] 4c 92 [2] 67 be [2] 49 9c [2] 5d 87 [2] 52 9d [2] 4c 80 [2] 4e 81 [2] 55 87 [2] 49 80 [2] 55 af }

  condition:
    any of them
}