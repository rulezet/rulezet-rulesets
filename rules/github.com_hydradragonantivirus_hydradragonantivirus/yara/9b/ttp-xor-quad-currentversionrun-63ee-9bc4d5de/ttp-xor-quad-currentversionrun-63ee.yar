rule TTP_XOR_QUAD_CurrentVersionRun_63ee {
  strings:
    $key_63ee = { 30 81 [2] 14 8f [2] 3f a3 [2] 11 81 [2] 05 9a [2] 0a 80 [2] 14 9d [2] 16 9c [2] 0d 9a [2] 11 9d [2] 0d b2 }

  condition:
    any of them
}