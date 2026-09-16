rule TTP_XOR_QUAD_CurrentVersionRun_284e {
  strings:
    $key_284e = { 7b 21 [2] 5f 2f [2] 74 03 [2] 5a 21 [2] 4e 3a [2] 41 20 [2] 5f 3d [2] 5d 3c [2] 46 3a [2] 5a 3d [2] 46 12 }

  condition:
    any of them
}