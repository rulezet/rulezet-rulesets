rule TTP_XOR_QUAD_CurrentVersionRun_fa3e {
  strings:
    $key_fa3e = { a9 51 [2] 8d 5f [2] a6 73 [2] 88 51 [2] 9c 4a [2] 93 50 [2] 8d 4d [2] 8f 4c [2] 94 4a [2] 88 4d [2] 94 62 }

  condition:
    any of them
}