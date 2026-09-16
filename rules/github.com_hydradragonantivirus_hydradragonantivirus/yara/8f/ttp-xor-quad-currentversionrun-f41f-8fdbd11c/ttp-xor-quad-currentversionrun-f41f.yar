rule TTP_XOR_QUAD_CurrentVersionRun_f41f {
  strings:
    $key_f41f = { a7 70 [2] 83 7e [2] a8 52 [2] 86 70 [2] 92 6b [2] 9d 71 [2] 83 6c [2] 81 6d [2] 9a 6b [2] 86 6c [2] 9a 43 }

  condition:
    any of them
}