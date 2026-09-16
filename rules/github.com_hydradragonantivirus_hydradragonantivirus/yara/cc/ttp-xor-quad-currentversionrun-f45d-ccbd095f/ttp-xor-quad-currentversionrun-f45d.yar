rule TTP_XOR_QUAD_CurrentVersionRun_f45d {
  strings:
    $key_f45d = { a7 32 [2] 83 3c [2] a8 10 [2] 86 32 [2] 92 29 [2] 9d 33 [2] 83 2e [2] 81 2f [2] 9a 29 [2] 86 2e [2] 9a 01 }

  condition:
    any of them
}