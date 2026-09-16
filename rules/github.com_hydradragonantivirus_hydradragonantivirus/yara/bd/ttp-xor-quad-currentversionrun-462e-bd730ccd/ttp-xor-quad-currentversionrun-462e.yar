rule TTP_XOR_QUAD_CurrentVersionRun_462e {
  strings:
    $key_462e = { 15 41 [2] 31 4f [2] 1a 63 [2] 34 41 [2] 20 5a [2] 2f 40 [2] 31 5d [2] 33 5c [2] 28 5a [2] 34 5d [2] 28 72 }

  condition:
    any of them
}