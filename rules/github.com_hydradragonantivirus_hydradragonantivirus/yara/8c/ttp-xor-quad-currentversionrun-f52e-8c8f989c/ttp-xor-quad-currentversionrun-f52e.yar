rule TTP_XOR_QUAD_CurrentVersionRun_f52e {
  strings:
    $key_f52e = { a6 41 [2] 82 4f [2] a9 63 [2] 87 41 [2] 93 5a [2] 9c 40 [2] 82 5d [2] 80 5c [2] 9b 5a [2] 87 5d [2] 9b 72 }

  condition:
    any of them
}