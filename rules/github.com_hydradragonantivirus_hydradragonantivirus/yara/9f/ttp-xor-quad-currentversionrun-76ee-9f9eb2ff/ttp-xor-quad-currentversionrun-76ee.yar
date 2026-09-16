rule TTP_XOR_QUAD_CurrentVersionRun_76ee {
  strings:
    $key_76ee = { 25 81 [2] 01 8f [2] 2a a3 [2] 04 81 [2] 10 9a [2] 1f 80 [2] 01 9d [2] 03 9c [2] 18 9a [2] 04 9d [2] 18 b2 }

  condition:
    any of them
}