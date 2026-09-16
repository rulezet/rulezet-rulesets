rule TTP_XOR_QUAD_CurrentVersionRun_f7e6 {
  strings:
    $key_f7e6 = { a4 89 [2] 80 87 [2] ab ab [2] 85 89 [2] 91 92 [2] 9e 88 [2] 80 95 [2] 82 94 [2] 99 92 [2] 85 95 [2] 99 ba }

  condition:
    any of them
}