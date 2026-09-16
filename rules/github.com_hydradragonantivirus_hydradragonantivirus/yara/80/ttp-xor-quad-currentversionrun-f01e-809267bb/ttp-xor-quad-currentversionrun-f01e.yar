rule TTP_XOR_QUAD_CurrentVersionRun_f01e {
  strings:
    $key_f01e = { a3 71 [2] 87 7f [2] ac 53 [2] 82 71 [2] 96 6a [2] 99 70 [2] 87 6d [2] 85 6c [2] 9e 6a [2] 82 6d [2] 9e 42 }

  condition:
    any of them
}