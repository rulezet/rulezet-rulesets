rule TTP_XOR_QUAD_CurrentVersionRun_f76a {
  strings:
    $key_f76a = { a4 05 [2] 80 0b [2] ab 27 [2] 85 05 [2] 91 1e [2] 9e 04 [2] 80 19 [2] 82 18 [2] 99 1e [2] 85 19 [2] 99 36 }

  condition:
    any of them
}