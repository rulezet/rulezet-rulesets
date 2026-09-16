rule TTP_XOR_QUAD_CurrentVersionRun_f51e {
  strings:
    $key_f51e = { a6 71 [2] 82 7f [2] a9 53 [2] 87 71 [2] 93 6a [2] 9c 70 [2] 82 6d [2] 80 6c [2] 9b 6a [2] 87 6d [2] 9b 42 }

  condition:
    any of them
}