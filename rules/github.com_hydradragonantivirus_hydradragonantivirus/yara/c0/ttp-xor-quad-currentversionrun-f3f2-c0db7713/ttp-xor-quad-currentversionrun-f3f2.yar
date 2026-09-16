rule TTP_XOR_QUAD_CurrentVersionRun_f3f2 {
  strings:
    $key_f3f2 = { a0 9d [2] 84 93 [2] af bf [2] 81 9d [2] 95 86 [2] 9a 9c [2] 84 81 [2] 86 80 [2] 9d 86 [2] 81 81 [2] 9d ae }

  condition:
    any of them
}