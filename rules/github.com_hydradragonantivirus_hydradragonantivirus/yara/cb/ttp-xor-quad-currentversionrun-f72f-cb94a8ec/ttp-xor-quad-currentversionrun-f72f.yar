rule TTP_XOR_QUAD_CurrentVersionRun_f72f {
  strings:
    $key_f72f = { a4 40 [2] 80 4e [2] ab 62 [2] 85 40 [2] 91 5b [2] 9e 41 [2] 80 5c [2] 82 5d [2] 99 5b [2] 85 5c [2] 99 73 }

  condition:
    any of them
}