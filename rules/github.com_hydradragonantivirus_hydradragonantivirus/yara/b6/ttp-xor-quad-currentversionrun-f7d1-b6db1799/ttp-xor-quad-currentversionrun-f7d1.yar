rule TTP_XOR_QUAD_CurrentVersionRun_f7d1 {
  strings:
    $key_f7d1 = { a4 be [2] 80 b0 [2] ab 9c [2] 85 be [2] 91 a5 [2] 9e bf [2] 80 a2 [2] 82 a3 [2] 99 a5 [2] 85 a2 [2] 99 8d }

  condition:
    any of them
}