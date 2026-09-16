rule TTP_XOR_QUAD_CurrentVersionRun_463e {
  strings:
    $key_463e = { 15 51 [2] 31 5f [2] 1a 73 [2] 34 51 [2] 20 4a [2] 2f 50 [2] 31 4d [2] 33 4c [2] 28 4a [2] 34 4d [2] 28 62 }

  condition:
    any of them
}