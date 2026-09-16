rule TTP_XOR_QUAD_CurrentVersionRun_f43e {
  strings:
    $key_f43e = { a7 51 [2] 83 5f [2] a8 73 [2] 86 51 [2] 92 4a [2] 9d 50 [2] 83 4d [2] 81 4c [2] 9a 4a [2] 86 4d [2] 9a 62 }

  condition:
    any of them
}