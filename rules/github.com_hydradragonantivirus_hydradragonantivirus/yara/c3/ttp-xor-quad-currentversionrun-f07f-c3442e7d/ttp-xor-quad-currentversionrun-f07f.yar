rule TTP_XOR_QUAD_CurrentVersionRun_f07f {
  strings:
    $key_f07f = { a3 10 [2] 87 1e [2] ac 32 [2] 82 10 [2] 96 0b [2] 99 11 [2] 87 0c [2] 85 0d [2] 9e 0b [2] 82 0c [2] 9e 23 }

  condition:
    any of them
}