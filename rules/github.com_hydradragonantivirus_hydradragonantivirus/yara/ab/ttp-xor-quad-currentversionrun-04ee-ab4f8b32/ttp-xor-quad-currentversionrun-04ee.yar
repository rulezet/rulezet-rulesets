rule TTP_XOR_QUAD_CurrentVersionRun_04ee {
  strings:
    $key_04ee = { 57 81 [2] 73 8f [2] 58 a3 [2] 76 81 [2] 62 9a [2] 6d 80 [2] 73 9d [2] 71 9c [2] 6a 9a [2] 76 9d [2] 6a b2 }

  condition:
    any of them
}