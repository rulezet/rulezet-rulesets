rule TTP_XOR_QUAD_CurrentVersionRun_f7f3 {
  strings:
    $key_f7f3 = { a4 9c [2] 80 92 [2] ab be [2] 85 9c [2] 91 87 [2] 9e 9d [2] 80 80 [2] 82 81 [2] 99 87 [2] 85 80 [2] 99 af }

  condition:
    any of them
}