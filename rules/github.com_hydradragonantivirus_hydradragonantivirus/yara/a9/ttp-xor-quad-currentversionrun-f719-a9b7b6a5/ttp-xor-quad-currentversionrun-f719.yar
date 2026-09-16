rule TTP_XOR_QUAD_CurrentVersionRun_f719 {
  strings:
    $key_f719 = { a4 76 [2] 80 78 [2] ab 54 [2] 85 76 [2] 91 6d [2] 9e 77 [2] 80 6a [2] 82 6b [2] 99 6d [2] 85 6a [2] 99 45 }

  condition:
    any of them
}