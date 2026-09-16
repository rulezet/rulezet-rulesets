rule TTP_XOR_QUAD_CurrentVersionRun_f41c {
  strings:
    $key_f41c = { a7 73 [2] 83 7d [2] a8 51 [2] 86 73 [2] 92 68 [2] 9d 72 [2] 83 6f [2] 81 6e [2] 9a 68 [2] 86 6f [2] 9a 40 }

  condition:
    any of them
}