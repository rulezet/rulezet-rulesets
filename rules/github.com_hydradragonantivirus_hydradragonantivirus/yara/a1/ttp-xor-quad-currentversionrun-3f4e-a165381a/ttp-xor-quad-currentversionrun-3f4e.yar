rule TTP_XOR_QUAD_CurrentVersionRun_3f4e {
  strings:
    $key_3f4e = { 6c 21 [2] 48 2f [2] 63 03 [2] 4d 21 [2] 59 3a [2] 56 20 [2] 48 3d [2] 4a 3c [2] 51 3a [2] 4d 3d [2] 51 12 }

  condition:
    any of them
}