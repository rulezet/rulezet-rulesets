rule TTP_XOR_QUAD_CurrentVersionRun_f05b {
  strings:
    $key_f05b = { a3 34 [2] 87 3a [2] ac 16 [2] 82 34 [2] 96 2f [2] 99 35 [2] 87 28 [2] 85 29 [2] 9e 2f [2] 82 28 [2] 9e 07 }

  condition:
    any of them
}