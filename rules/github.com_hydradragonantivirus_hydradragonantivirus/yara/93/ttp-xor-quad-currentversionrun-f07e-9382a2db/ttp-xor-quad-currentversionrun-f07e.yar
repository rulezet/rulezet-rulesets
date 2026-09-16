rule TTP_XOR_QUAD_CurrentVersionRun_f07e {
  strings:
    $key_f07e = { a3 11 [2] 87 1f [2] ac 33 [2] 82 11 [2] 96 0a [2] 99 10 [2] 87 0d [2] 85 0c [2] 9e 0a [2] 82 0d [2] 9e 22 }

  condition:
    any of them
}