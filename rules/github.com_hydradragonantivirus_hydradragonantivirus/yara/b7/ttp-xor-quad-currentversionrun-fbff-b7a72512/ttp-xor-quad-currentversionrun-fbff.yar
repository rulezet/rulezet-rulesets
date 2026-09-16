rule TTP_XOR_QUAD_CurrentVersionRun_fbff {
  strings:
    $key_fbff = { a8 90 [2] 8c 9e [2] a7 b2 [2] 89 90 [2] 9d 8b [2] 92 91 [2] 8c 8c [2] 8e 8d [2] 95 8b [2] 89 8c [2] 95 a3 }

  condition:
    any of them
}