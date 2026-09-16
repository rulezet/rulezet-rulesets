rule TTP_XOR_QUAD_CurrentVersionRun_4a12 {
  strings:
    $key_4a12 = { 19 7d [2] 3d 73 [2] 16 5f [2] 38 7d [2] 2c 66 [2] 23 7c [2] 3d 61 [2] 3f 60 [2] 24 66 [2] 38 61 [2] 24 4e }

  condition:
    any of them
}