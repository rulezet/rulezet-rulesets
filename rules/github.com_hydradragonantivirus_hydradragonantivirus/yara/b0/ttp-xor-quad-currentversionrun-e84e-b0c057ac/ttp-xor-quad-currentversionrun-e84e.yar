rule TTP_XOR_QUAD_CurrentVersionRun_e84e {
  strings:
    $key_e84e = { bb 21 [2] 9f 2f [2] b4 03 [2] 9a 21 [2] 8e 3a [2] 81 20 [2] 9f 3d [2] 9d 3c [2] 86 3a [2] 9a 3d [2] 86 12 }

  condition:
    any of them
}