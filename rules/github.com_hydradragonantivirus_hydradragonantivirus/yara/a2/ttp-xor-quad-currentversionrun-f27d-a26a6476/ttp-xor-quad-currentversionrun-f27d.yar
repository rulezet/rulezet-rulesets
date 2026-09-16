rule TTP_XOR_QUAD_CurrentVersionRun_f27d {
  strings:
    $key_f27d = { a1 12 [2] 85 1c [2] ae 30 [2] 80 12 [2] 94 09 [2] 9b 13 [2] 85 0e [2] 87 0f [2] 9c 09 [2] 80 0e [2] 9c 21 }

  condition:
    any of them
}