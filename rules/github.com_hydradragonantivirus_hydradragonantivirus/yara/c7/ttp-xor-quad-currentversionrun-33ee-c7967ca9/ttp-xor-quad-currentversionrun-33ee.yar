rule TTP_XOR_QUAD_CurrentVersionRun_33ee {
  strings:
    $key_33ee = { 60 81 [2] 44 8f [2] 6f a3 [2] 41 81 [2] 55 9a [2] 5a 80 [2] 44 9d [2] 46 9c [2] 5d 9a [2] 41 9d [2] 5d b2 }

  condition:
    any of them
}