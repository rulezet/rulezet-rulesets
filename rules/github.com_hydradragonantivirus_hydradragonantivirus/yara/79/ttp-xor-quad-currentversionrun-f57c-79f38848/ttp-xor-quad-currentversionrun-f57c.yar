rule TTP_XOR_QUAD_CurrentVersionRun_f57c {
  strings:
    $key_f57c = { a6 13 [2] 82 1d [2] a9 31 [2] 87 13 [2] 93 08 [2] 9c 12 [2] 82 0f [2] 80 0e [2] 9b 08 [2] 87 0f [2] 9b 20 }

  condition:
    any of them
}