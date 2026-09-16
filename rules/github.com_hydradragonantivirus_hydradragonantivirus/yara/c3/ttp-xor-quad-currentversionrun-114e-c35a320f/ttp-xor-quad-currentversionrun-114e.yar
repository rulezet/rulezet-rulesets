rule TTP_XOR_QUAD_CurrentVersionRun_114e {
  strings:
    $key_114e = { 42 21 [2] 66 2f [2] 4d 03 [2] 63 21 [2] 77 3a [2] 78 20 [2] 66 3d [2] 64 3c [2] 7f 3a [2] 63 3d [2] 7f 12 }

  condition:
    any of them
}