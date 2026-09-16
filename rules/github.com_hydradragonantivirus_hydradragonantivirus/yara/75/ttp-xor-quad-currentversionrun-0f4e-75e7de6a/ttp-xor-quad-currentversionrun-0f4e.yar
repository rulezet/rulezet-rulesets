rule TTP_XOR_QUAD_CurrentVersionRun_0f4e {
  strings:
    $key_0f4e = { 5c 21 [2] 78 2f [2] 53 03 [2] 7d 21 [2] 69 3a [2] 66 20 [2] 78 3d [2] 7a 3c [2] 61 3a [2] 7d 3d [2] 61 12 }

  condition:
    any of them
}