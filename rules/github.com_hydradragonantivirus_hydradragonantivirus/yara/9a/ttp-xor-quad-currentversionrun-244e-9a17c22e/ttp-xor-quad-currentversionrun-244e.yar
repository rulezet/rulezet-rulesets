rule TTP_XOR_QUAD_CurrentVersionRun_244e {
  strings:
    $key_244e = { 77 21 [2] 53 2f [2] 78 03 [2] 56 21 [2] 42 3a [2] 4d 20 [2] 53 3d [2] 51 3c [2] 4a 3a [2] 56 3d [2] 4a 12 }

  condition:
    any of them
}