rule TTP_XOR_QUAD_CurrentVersionRun_f72b {
  strings:
    $key_f72b = { a4 44 [2] 80 4a [2] ab 66 [2] 85 44 [2] 91 5f [2] 9e 45 [2] 80 58 [2] 82 59 [2] 99 5f [2] 85 58 [2] 99 77 }

  condition:
    any of them
}