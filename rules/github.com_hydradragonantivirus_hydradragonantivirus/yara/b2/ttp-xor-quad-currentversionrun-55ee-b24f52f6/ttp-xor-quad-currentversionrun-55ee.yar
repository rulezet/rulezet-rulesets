rule TTP_XOR_QUAD_CurrentVersionRun_55ee {
  strings:
    $key_55ee = { 06 81 [2] 22 8f [2] 09 a3 [2] 27 81 [2] 33 9a [2] 3c 80 [2] 22 9d [2] 20 9c [2] 3b 9a [2] 27 9d [2] 3b b2 }

  condition:
    any of them
}