rule TTP_XOR_QUAD_CurrentVersionRun_004e {
  strings:
    $key_004e = { 53 21 [2] 77 2f [2] 5c 03 [2] 72 21 [2] 66 3a [2] 69 20 [2] 77 3d [2] 75 3c [2] 6e 3a [2] 72 3d [2] 6e 12 }

  condition:
    any of them
}