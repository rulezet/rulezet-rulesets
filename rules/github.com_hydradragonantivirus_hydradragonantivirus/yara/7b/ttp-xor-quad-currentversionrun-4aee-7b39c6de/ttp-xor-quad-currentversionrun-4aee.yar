rule TTP_XOR_QUAD_CurrentVersionRun_4aee {
  strings:
    $key_4aee = { 19 81 [2] 3d 8f [2] 16 a3 [2] 38 81 [2] 2c 9a [2] 23 80 [2] 3d 9d [2] 3f 9c [2] 24 9a [2] 38 9d [2] 24 b2 }

  condition:
    any of them
}