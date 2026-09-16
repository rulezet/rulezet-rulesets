rule TTP_XOR_QUAD_CurrentVersionRun_4a2e {
  strings:
    $key_4a2e = { 19 41 [2] 3d 4f [2] 16 63 [2] 38 41 [2] 2c 5a [2] 23 40 [2] 3d 5d [2] 3f 5c [2] 24 5a [2] 38 5d [2] 24 72 }

  condition:
    any of them
}