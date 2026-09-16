rule TTP_XOR_QUAD_CurrentVersionRun_4a1e {
  strings:
    $key_4a1e = { 19 71 [2] 3d 7f [2] 16 53 [2] 38 71 [2] 2c 6a [2] 23 70 [2] 3d 6d [2] 3f 6c [2] 24 6a [2] 38 6d [2] 24 42 }

  condition:
    any of them
}