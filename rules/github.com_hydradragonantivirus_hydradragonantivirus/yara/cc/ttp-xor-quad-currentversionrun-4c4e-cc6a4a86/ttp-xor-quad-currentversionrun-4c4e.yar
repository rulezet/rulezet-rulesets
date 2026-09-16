rule TTP_XOR_QUAD_CurrentVersionRun_4c4e {
  strings:
    $key_4c4e = { 1f 21 [2] 3b 2f [2] 10 03 [2] 3e 21 [2] 2a 3a [2] 25 20 [2] 3b 3d [2] 39 3c [2] 22 3a [2] 3e 3d [2] 22 12 }

  condition:
    any of them
}