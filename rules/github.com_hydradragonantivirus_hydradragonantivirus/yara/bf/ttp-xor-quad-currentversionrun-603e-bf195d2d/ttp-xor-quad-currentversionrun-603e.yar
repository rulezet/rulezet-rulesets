rule TTP_XOR_QUAD_CurrentVersionRun_603e {
  strings:
    $key_603e = { 33 51 [2] 17 5f [2] 3c 73 [2] 12 51 [2] 06 4a [2] 09 50 [2] 17 4d [2] 15 4c [2] 0e 4a [2] 12 4d [2] 0e 62 }

  condition:
    any of them
}