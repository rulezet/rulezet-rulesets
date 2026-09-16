rule TTP_XOR_QUAD_CurrentVersionRun_f0bf {
  strings:
    $key_f0bf = { a3 d0 [2] 87 de [2] ac f2 [2] 82 d0 [2] 96 cb [2] 99 d1 [2] 87 cc [2] 85 cd [2] 9e cb [2] 82 cc [2] 9e e3 }

  condition:
    any of them
}