rule TTP_XOR_QUAD_CurrentVersionRun_f72e {
  strings:
    $key_f72e = { a4 41 [2] 80 4f [2] ab 63 [2] 85 41 [2] 91 5a [2] 9e 40 [2] 80 5d [2] 82 5c [2] 99 5a [2] 85 5d [2] 99 72 }

  condition:
    any of them
}