rule TTP_XOR_QUAD_CurrentVersionRun_f704 {
  strings:
    $key_f704 = { a4 6b [2] 80 65 [2] ab 49 [2] 85 6b [2] 91 70 [2] 9e 6a [2] 80 77 [2] 82 76 [2] 99 70 [2] 85 77 [2] 99 58 }

  condition:
    any of them
}