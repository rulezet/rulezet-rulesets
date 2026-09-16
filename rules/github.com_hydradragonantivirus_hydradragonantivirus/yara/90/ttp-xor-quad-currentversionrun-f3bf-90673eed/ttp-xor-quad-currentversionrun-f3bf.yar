rule TTP_XOR_QUAD_CurrentVersionRun_f3bf {
  strings:
    $key_f3bf = { a0 d0 [2] 84 de [2] af f2 [2] 81 d0 [2] 95 cb [2] 9a d1 [2] 84 cc [2] 86 cd [2] 9d cb [2] 81 cc [2] 9d e3 }

  condition:
    any of them
}