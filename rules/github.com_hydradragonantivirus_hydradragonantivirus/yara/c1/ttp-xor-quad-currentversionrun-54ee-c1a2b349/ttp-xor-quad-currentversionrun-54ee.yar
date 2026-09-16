rule TTP_XOR_QUAD_CurrentVersionRun_54ee {
  strings:
    $key_54ee = { 07 81 [2] 23 8f [2] 08 a3 [2] 26 81 [2] 32 9a [2] 3d 80 [2] 23 9d [2] 21 9c [2] 3a 9a [2] 26 9d [2] 3a b2 }

  condition:
    any of them
}