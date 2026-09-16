rule TTP_XOR_QUAD_CurrentVersionRun_e5f3 {
  strings:
    $key_e5f3 = { b6 9c [2] 92 92 [2] b9 be [2] 97 9c [2] 83 87 [2] 8c 9d [2] 92 80 [2] 90 81 [2] 8b 87 [2] 97 80 [2] 8b af }

  condition:
    any of them
}