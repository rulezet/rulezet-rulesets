rule TTP_XOR_QUAD_CurrentVersionRun_4aeb {
  strings:
    $key_4aeb = { 19 84 [2] 3d 8a [2] 16 a6 [2] 38 84 [2] 2c 9f [2] 23 85 [2] 3d 98 [2] 3f 99 [2] 24 9f [2] 38 98 [2] 24 b7 }

  condition:
    any of them
}