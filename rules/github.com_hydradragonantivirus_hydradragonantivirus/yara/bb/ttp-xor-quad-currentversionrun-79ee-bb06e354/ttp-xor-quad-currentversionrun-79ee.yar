rule TTP_XOR_QUAD_CurrentVersionRun_79ee {
  strings:
    $key_79ee = { 2a 81 [2] 0e 8f [2] 25 a3 [2] 0b 81 [2] 1f 9a [2] 10 80 [2] 0e 9d [2] 0c 9c [2] 17 9a [2] 0b 9d [2] 17 b2 }

  condition:
    any of them
}