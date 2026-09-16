rule TTP_XOR_QUAD_CurrentVersionRun_464e {
  strings:
    $key_464e = { 15 21 [2] 31 2f [2] 1a 03 [2] 34 21 [2] 20 3a [2] 2f 20 [2] 31 3d [2] 33 3c [2] 28 3a [2] 34 3d [2] 28 12 }

  condition:
    any of them
}