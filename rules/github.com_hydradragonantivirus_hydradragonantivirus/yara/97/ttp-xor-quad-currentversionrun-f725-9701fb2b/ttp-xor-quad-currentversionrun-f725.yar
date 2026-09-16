rule TTP_XOR_QUAD_CurrentVersionRun_f725 {
  strings:
    $key_f725 = { a4 4a [2] 80 44 [2] ab 68 [2] 85 4a [2] 91 51 [2] 9e 4b [2] 80 56 [2] 82 57 [2] 99 51 [2] 85 56 [2] 99 79 }

  condition:
    any of them
}