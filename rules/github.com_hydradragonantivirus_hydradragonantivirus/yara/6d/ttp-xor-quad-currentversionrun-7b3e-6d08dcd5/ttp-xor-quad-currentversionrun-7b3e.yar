rule TTP_XOR_QUAD_CurrentVersionRun_7b3e {
  strings:
    $key_7b3e = { 28 51 [2] 0c 5f [2] 27 73 [2] 09 51 [2] 1d 4a [2] 12 50 [2] 0c 4d [2] 0e 4c [2] 15 4a [2] 09 4d [2] 15 62 }

  condition:
    any of them
}