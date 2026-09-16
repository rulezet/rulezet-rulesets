rule TTP_XOR_QUAD_CurrentVersionRun_20ee {
  strings:
    $key_20ee = { 73 81 [2] 57 8f [2] 7c a3 [2] 52 81 [2] 46 9a [2] 49 80 [2] 57 9d [2] 55 9c [2] 4e 9a [2] 52 9d [2] 4e b2 }

  condition:
    any of them
}