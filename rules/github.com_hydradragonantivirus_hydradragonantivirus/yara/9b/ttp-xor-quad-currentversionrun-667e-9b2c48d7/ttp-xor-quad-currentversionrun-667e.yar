rule TTP_XOR_QUAD_CurrentVersionRun_667e {
  strings:
    $key_667e = { 35 11 [2] 11 1f [2] 3a 33 [2] 14 11 [2] 00 0a [2] 0f 10 [2] 11 0d [2] 13 0c [2] 08 0a [2] 14 0d [2] 08 22 }

  condition:
    any of them
}