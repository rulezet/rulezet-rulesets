rule TTP_XOR_QUAD_CurrentVersionRun_f713 {
  strings:
    $key_f713 = { a4 7c [2] 80 72 [2] ab 5e [2] 85 7c [2] 91 67 [2] 9e 7d [2] 80 60 [2] 82 61 [2] 99 67 [2] 85 60 [2] 99 4f }

  condition:
    any of them
}