rule TTP_XOR_QUAD_CurrentVersionRun_134e {
  strings:
    $key_134e = { 40 21 [2] 64 2f [2] 4f 03 [2] 61 21 [2] 75 3a [2] 7a 20 [2] 64 3d [2] 66 3c [2] 7d 3a [2] 61 3d [2] 7d 12 }

  condition:
    any of them
}