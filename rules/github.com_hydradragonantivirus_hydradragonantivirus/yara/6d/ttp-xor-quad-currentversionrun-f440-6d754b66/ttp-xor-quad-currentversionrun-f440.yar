rule TTP_XOR_QUAD_CurrentVersionRun_f440 {
  strings:
    $key_f440 = { a7 2f [2] 83 21 [2] a8 0d [2] 86 2f [2] 92 34 [2] 9d 2e [2] 83 33 [2] 81 32 [2] 9a 34 [2] 86 33 [2] 9a 1c }

  condition:
    any of them
}