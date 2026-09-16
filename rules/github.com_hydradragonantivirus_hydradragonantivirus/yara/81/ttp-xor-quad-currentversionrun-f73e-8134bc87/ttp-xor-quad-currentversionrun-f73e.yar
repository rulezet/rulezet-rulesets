rule TTP_XOR_QUAD_CurrentVersionRun_f73e {
  strings:
    $key_f73e = { a4 51 [2] 80 5f [2] ab 73 [2] 85 51 [2] 91 4a [2] 9e 50 [2] 80 4d [2] 82 4c [2] 99 4a [2] 85 4d [2] 99 62 }

  condition:
    any of them
}