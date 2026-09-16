rule TTP_XOR_QUAD_CurrentVersionRun_f44f {
  strings:
    $key_f44f = { a7 20 [2] 83 2e [2] a8 02 [2] 86 20 [2] 92 3b [2] 9d 21 [2] 83 3c [2] 81 3d [2] 9a 3b [2] 86 3c [2] 9a 13 }

  condition:
    any of them
}