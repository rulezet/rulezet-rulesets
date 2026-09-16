rule TTP_XOR_QUAD_CurrentVersionRun_602e {
  strings:
    $key_602e = { 33 41 [2] 17 4f [2] 3c 63 [2] 12 41 [2] 06 5a [2] 09 40 [2] 17 5d [2] 15 5c [2] 0e 5a [2] 12 5d [2] 0e 72 }

  condition:
    any of them
}