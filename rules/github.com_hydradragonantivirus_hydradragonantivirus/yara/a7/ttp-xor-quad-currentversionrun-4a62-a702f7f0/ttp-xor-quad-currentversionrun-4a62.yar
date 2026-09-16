rule TTP_XOR_QUAD_CurrentVersionRun_4a62 {
  strings:
    $key_4a62 = { 19 0d [2] 3d 03 [2] 16 2f [2] 38 0d [2] 2c 16 [2] 23 0c [2] 3d 11 [2] 3f 10 [2] 24 16 [2] 38 11 [2] 24 3e }

  condition:
    any of them
}