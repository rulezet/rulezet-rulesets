rule TTP_XOR_QUAD_CurrentVersionRun_74ee {
  strings:
    $key_74ee = { 27 81 [2] 03 8f [2] 28 a3 [2] 06 81 [2] 12 9a [2] 1d 80 [2] 03 9d [2] 01 9c [2] 1a 9a [2] 06 9d [2] 1a b2 }

  condition:
    any of them
}