rule TTP_XOR_QUAD_CurrentVersionRun_6cf3 {
  strings:
    $key_6cf3 = { 3f 9c [2] 1b 92 [2] 30 be [2] 1e 9c [2] 0a 87 [2] 05 9d [2] 1b 80 [2] 19 81 [2] 02 87 [2] 1e 80 [2] 02 af }

  condition:
    any of them
}