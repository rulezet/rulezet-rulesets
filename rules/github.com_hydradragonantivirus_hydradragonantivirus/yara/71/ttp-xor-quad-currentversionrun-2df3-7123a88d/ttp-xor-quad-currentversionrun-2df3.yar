rule TTP_XOR_QUAD_CurrentVersionRun_2df3 {
  strings:
    $key_2df3 = { 7e 9c [2] 5a 92 [2] 71 be [2] 5f 9c [2] 4b 87 [2] 44 9d [2] 5a 80 [2] 58 81 [2] 43 87 [2] 5f 80 [2] 43 af }

  condition:
    any of them
}