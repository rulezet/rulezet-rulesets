rule TTP_XOR_QUAD_CurrentVersionRun_1bf3 {
  strings:
    $key_1bf3 = { 48 9c [2] 6c 92 [2] 47 be [2] 69 9c [2] 7d 87 [2] 72 9d [2] 6c 80 [2] 6e 81 [2] 75 87 [2] 69 80 [2] 75 af }

  condition:
    any of them
}