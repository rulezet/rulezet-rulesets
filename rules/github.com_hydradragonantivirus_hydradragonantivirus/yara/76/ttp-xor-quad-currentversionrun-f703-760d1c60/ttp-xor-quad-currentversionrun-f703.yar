rule TTP_XOR_QUAD_CurrentVersionRun_f703 {
  strings:
    $key_f703 = { a4 6c [2] 80 62 [2] ab 4e [2] 85 6c [2] 91 77 [2] 9e 6d [2] 80 70 [2] 82 71 [2] 99 77 [2] 85 70 [2] 99 5f }

  condition:
    any of them
}