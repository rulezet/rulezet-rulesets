rule TTP_XOR_QUAD_CurrentVersionRun_f43f {
  strings:
    $key_f43f = { a7 50 [2] 83 5e [2] a8 72 [2] 86 50 [2] 92 4b [2] 9d 51 [2] 83 4c [2] 81 4d [2] 9a 4b [2] 86 4c [2] 9a 63 }

  condition:
    any of them
}