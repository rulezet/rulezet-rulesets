rule TTP_XOR_QUAD_CurrentVersionRun_f733 {
  strings:
    $key_f733 = { a4 5c [2] 80 52 [2] ab 7e [2] 85 5c [2] 91 47 [2] 9e 5d [2] 80 40 [2] 82 41 [2] 99 47 [2] 85 40 [2] 99 6f }

  condition:
    any of them
}