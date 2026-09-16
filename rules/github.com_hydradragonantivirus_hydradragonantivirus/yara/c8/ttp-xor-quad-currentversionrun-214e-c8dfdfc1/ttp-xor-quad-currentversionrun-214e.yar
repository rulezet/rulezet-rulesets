rule TTP_XOR_QUAD_CurrentVersionRun_214e {
  strings:
    $key_214e = { 72 21 [2] 56 2f [2] 7d 03 [2] 53 21 [2] 47 3a [2] 48 20 [2] 56 3d [2] 54 3c [2] 4f 3a [2] 53 3d [2] 4f 12 }

  condition:
    any of them
}