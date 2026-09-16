rule TTP_XOR_QUAD_CurrentVersionRun_634e {
  strings:
    $key_634e = { 30 21 [2] 14 2f [2] 3f 03 [2] 11 21 [2] 05 3a [2] 0a 20 [2] 14 3d [2] 16 3c [2] 0d 3a [2] 11 3d [2] 0d 12 }

  condition:
    any of them
}