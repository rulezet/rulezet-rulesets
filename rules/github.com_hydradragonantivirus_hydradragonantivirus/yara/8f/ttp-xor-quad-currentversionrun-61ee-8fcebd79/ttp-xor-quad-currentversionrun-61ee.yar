rule TTP_XOR_QUAD_CurrentVersionRun_61ee {
  strings:
    $key_61ee = { 32 81 [2] 16 8f [2] 3d a3 [2] 13 81 [2] 07 9a [2] 08 80 [2] 16 9d [2] 14 9c [2] 0f 9a [2] 13 9d [2] 0f b2 }

  condition:
    any of them
}