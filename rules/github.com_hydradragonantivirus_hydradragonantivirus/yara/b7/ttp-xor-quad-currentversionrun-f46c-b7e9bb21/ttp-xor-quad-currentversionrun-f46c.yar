rule TTP_XOR_QUAD_CurrentVersionRun_f46c {
  strings:
    $key_f46c = { a7 03 [2] 83 0d [2] a8 21 [2] 86 03 [2] 92 18 [2] 9d 02 [2] 83 1f [2] 81 1e [2] 9a 18 [2] 86 1f [2] 9a 30 }

  condition:
    any of them
}