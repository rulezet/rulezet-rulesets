rule TTP_XOR_QUAD_CurrentVersionRun_f736 {
  strings:
    $key_f736 = { a4 59 [2] 80 57 [2] ab 7b [2] 85 59 [2] 91 42 [2] 9e 58 [2] 80 45 [2] 82 44 [2] 99 42 [2] 85 45 [2] 99 6a }

  condition:
    any of them
}