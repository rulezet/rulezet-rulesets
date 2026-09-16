rule TTP_XOR_QUAD_CurrentVersionRun_204e {
  strings:
    $key_204e = { 73 21 [2] 57 2f [2] 7c 03 [2] 52 21 [2] 46 3a [2] 49 20 [2] 57 3d [2] 55 3c [2] 4e 3a [2] 52 3d [2] 4e 12 }

  condition:
    any of them
}