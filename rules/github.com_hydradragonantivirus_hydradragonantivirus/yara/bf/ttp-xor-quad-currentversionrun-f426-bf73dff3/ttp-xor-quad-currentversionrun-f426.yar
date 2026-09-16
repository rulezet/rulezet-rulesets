rule TTP_XOR_QUAD_CurrentVersionRun_f426 {
  strings:
    $key_f426 = { a7 49 [2] 83 47 [2] a8 6b [2] 86 49 [2] 92 52 [2] 9d 48 [2] 83 55 [2] 81 54 [2] 9a 52 [2] 86 55 [2] 9a 7a }

  condition:
    any of them
}