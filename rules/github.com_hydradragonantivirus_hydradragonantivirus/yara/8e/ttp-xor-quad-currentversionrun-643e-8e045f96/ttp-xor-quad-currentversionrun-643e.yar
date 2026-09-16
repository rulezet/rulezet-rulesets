rule TTP_XOR_QUAD_CurrentVersionRun_643e {
  strings:
    $key_643e = { 37 51 [2] 13 5f [2] 38 73 [2] 16 51 [2] 02 4a [2] 0d 50 [2] 13 4d [2] 11 4c [2] 0a 4a [2] 16 4d [2] 0a 62 }

  condition:
    any of them
}