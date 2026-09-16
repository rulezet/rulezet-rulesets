rule TTP_XOR_QUAD_CurrentVersionRun_f710 {
  strings:
    $key_f710 = { a4 7f [2] 80 71 [2] ab 5d [2] 85 7f [2] 91 64 [2] 9e 7e [2] 80 63 [2] 82 62 [2] 99 64 [2] 85 63 [2] 99 4c }

  condition:
    any of them
}