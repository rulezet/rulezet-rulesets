rule TTP_XOR_QUAD_CurrentVersionRun_f709 {
  strings:
    $key_f709 = { a4 66 [2] 80 68 [2] ab 44 [2] 85 66 [2] 91 7d [2] 9e 67 [2] 80 7a [2] 82 7b [2] 99 7d [2] 85 7a [2] 99 55 }

  condition:
    any of them
}