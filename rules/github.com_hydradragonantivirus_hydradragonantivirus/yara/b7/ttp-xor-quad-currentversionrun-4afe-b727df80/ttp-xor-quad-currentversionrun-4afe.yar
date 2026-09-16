rule TTP_XOR_QUAD_CurrentVersionRun_4afe {
  strings:
    $key_4afe = { 19 91 [2] 3d 9f [2] 16 b3 [2] 38 91 [2] 2c 8a [2] 23 90 [2] 3d 8d [2] 3f 8c [2] 24 8a [2] 38 8d [2] 24 a2 }

  condition:
    any of them
}