rule TTP_XOR_QUAD_CurrentVersionRun_6bf3 {
  strings:
    $key_6bf3 = { 38 9c [2] 1c 92 [2] 37 be [2] 19 9c [2] 0d 87 [2] 02 9d [2] 1c 80 [2] 1e 81 [2] 05 87 [2] 19 80 [2] 05 af }

  condition:
    any of them
}