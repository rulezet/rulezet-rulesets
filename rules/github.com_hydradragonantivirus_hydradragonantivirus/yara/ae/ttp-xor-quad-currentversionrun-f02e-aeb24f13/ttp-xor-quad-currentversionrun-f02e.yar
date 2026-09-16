rule TTP_XOR_QUAD_CurrentVersionRun_f02e {
  strings:
    $key_f02e = { a3 41 [2] 87 4f [2] ac 63 [2] 82 41 [2] 96 5a [2] 99 40 [2] 87 5d [2] 85 5c [2] 9e 5a [2] 82 5d [2] 9e 72 }

  condition:
    any of them
}