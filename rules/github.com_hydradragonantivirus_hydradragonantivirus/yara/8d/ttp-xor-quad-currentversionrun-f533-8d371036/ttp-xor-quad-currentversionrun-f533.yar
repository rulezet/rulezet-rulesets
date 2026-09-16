rule TTP_XOR_QUAD_CurrentVersionRun_f533 {
  strings:
    $key_f533 = { a6 5c [2] 82 52 [2] a9 7e [2] 87 5c [2] 93 47 [2] 9c 5d [2] 82 40 [2] 80 41 [2] 9b 47 [2] 87 40 [2] 9b 6f }

  condition:
    any of them
}