rule TTP_XOR_QUAD_CurrentVersionRun_47ee {
  strings:
    $key_47ee = { 14 81 [2] 30 8f [2] 1b a3 [2] 35 81 [2] 21 9a [2] 2e 80 [2] 30 9d [2] 32 9c [2] 29 9a [2] 35 9d [2] 29 b2 }

  condition:
    any of them
}