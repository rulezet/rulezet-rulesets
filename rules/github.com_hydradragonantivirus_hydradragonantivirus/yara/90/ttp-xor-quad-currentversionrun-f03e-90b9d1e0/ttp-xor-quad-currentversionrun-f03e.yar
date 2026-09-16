rule TTP_XOR_QUAD_CurrentVersionRun_f03e {
  strings:
    $key_f03e = { a3 51 [2] 87 5f [2] ac 73 [2] 82 51 [2] 96 4a [2] 99 50 [2] 87 4d [2] 85 4c [2] 9e 4a [2] 82 4d [2] 9e 62 }

  condition:
    any of them
}