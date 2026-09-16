rule TTP_XOR_QUAD_CurrentVersionRun_f42c {
  strings:
    $key_f42c = { a7 43 [2] 83 4d [2] a8 61 [2] 86 43 [2] 92 58 [2] 9d 42 [2] 83 5f [2] 81 5e [2] 9a 58 [2] 86 5f [2] 9a 70 }

  condition:
    any of them
}