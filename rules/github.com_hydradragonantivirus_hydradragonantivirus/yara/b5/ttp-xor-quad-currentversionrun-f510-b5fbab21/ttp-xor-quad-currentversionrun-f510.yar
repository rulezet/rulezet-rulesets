rule TTP_XOR_QUAD_CurrentVersionRun_f510 {
  strings:
    $key_f510 = { a6 7f [2] 82 71 [2] a9 5d [2] 87 7f [2] 93 64 [2] 9c 7e [2] 82 63 [2] 80 62 [2] 9b 64 [2] 87 63 [2] 9b 4c }

  condition:
    any of them
}