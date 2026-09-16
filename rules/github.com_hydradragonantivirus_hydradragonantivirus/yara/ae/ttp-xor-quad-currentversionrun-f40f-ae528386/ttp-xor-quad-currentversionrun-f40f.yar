rule TTP_XOR_QUAD_CurrentVersionRun_f40f {
  strings:
    $key_f40f = { a7 60 [2] 83 6e [2] a8 42 [2] 86 60 [2] 92 7b [2] 9d 61 [2] 83 7c [2] 81 7d [2] 9a 7b [2] 86 7c [2] 9a 53 }

  condition:
    any of them
}