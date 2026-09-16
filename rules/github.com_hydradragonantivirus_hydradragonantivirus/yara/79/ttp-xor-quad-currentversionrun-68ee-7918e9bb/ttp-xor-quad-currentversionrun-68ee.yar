rule TTP_XOR_QUAD_CurrentVersionRun_68ee {
  strings:
    $key_68ee = { 3b 81 [2] 1f 8f [2] 34 a3 [2] 1a 81 [2] 0e 9a [2] 01 80 [2] 1f 9d [2] 1d 9c [2] 06 9a [2] 1a 9d [2] 06 b2 }

  condition:
    any of them
}