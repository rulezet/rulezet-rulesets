rule TTP_XOR_QUAD_CurrentVersionRun_f401 {
  strings:
    $key_f401 = { a7 6e [2] 83 60 [2] a8 4c [2] 86 6e [2] 92 75 [2] 9d 6f [2] 83 72 [2] 81 73 [2] 9a 75 [2] 86 72 [2] 9a 5d }

  condition:
    any of them
}