rule TTP_XOR_QUAD_CurrentVersionRun_49ee {
  strings:
    $key_49ee = { 1a 81 [2] 3e 8f [2] 15 a3 [2] 3b 81 [2] 2f 9a [2] 20 80 [2] 3e 9d [2] 3c 9c [2] 27 9a [2] 3b 9d [2] 27 b2 }

  condition:
    any of them
}