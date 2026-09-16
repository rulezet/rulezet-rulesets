rule TTP_XOR_QUAD_CurrentVersionRun_f27e {
  strings:
    $key_f27e = { a1 11 [2] 85 1f [2] ae 33 [2] 80 11 [2] 94 0a [2] 9b 10 [2] 85 0d [2] 87 0c [2] 9c 0a [2] 80 0d [2] 9c 22 }

  condition:
    any of them
}