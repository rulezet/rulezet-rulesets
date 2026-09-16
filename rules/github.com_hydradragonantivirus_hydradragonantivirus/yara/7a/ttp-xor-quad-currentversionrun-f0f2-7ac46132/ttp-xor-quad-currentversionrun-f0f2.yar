rule TTP_XOR_QUAD_CurrentVersionRun_f0f2 {
  strings:
    $key_f0f2 = { a3 9d [2] 87 93 [2] ac bf [2] 82 9d [2] 96 86 [2] 99 9c [2] 87 81 [2] 85 80 [2] 9e 86 [2] 82 81 [2] 9e ae }

  condition:
    any of them
}