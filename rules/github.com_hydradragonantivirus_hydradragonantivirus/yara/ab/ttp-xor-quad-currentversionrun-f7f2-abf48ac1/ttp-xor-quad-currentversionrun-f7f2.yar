rule TTP_XOR_QUAD_CurrentVersionRun_f7f2 {
  strings:
    $key_f7f2 = { a4 9d [2] 80 93 [2] ab bf [2] 85 9d [2] 91 86 [2] 9e 9c [2] 80 81 [2] 82 80 [2] 99 86 [2] 85 81 [2] 99 ae }

  condition:
    any of them
}