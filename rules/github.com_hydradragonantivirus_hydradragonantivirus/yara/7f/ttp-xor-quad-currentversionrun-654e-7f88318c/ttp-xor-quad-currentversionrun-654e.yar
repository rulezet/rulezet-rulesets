rule TTP_XOR_QUAD_CurrentVersionRun_654e {
  strings:
    $key_654e = { 36 21 [2] 12 2f [2] 39 03 [2] 17 21 [2] 03 3a [2] 0c 20 [2] 12 3d [2] 10 3c [2] 0b 3a [2] 17 3d [2] 0b 12 }

  condition:
    any of them
}