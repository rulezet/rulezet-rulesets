rule TTP_XOR_QUAD_CurrentVersionRun_06ee {
  strings:
    $key_06ee = { 55 81 [2] 71 8f [2] 5a a3 [2] 74 81 [2] 60 9a [2] 6f 80 [2] 71 9d [2] 73 9c [2] 68 9a [2] 74 9d [2] 68 b2 }

  condition:
    any of them
}