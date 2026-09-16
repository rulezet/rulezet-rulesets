rule TTP_XOR_QUAD_CurrentVersionRun_f47f {
  strings:
    $key_f47f = { a7 10 [2] 83 1e [2] a8 32 [2] 86 10 [2] 92 0b [2] 9d 11 [2] 83 0c [2] 81 0d [2] 9a 0b [2] 86 0c [2] 9a 23 }

  condition:
    any of them
}