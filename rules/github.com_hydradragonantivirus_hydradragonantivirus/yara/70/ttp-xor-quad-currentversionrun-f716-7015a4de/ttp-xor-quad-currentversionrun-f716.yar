rule TTP_XOR_QUAD_CurrentVersionRun_f716 {
  strings:
    $key_f716 = { a4 79 [2] 80 77 [2] ab 5b [2] 85 79 [2] 91 62 [2] 9e 78 [2] 80 65 [2] 82 64 [2] 99 62 [2] 85 65 [2] 99 4a }

  condition:
    any of them
}