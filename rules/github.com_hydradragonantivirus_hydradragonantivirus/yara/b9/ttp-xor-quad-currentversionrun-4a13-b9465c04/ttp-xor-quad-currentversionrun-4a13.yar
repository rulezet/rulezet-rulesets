rule TTP_XOR_QUAD_CurrentVersionRun_4a13 {
  strings:
    $key_4a13 = { 19 7c [2] 3d 72 [2] 16 5e [2] 38 7c [2] 2c 67 [2] 23 7d [2] 3d 60 [2] 3f 61 [2] 24 67 [2] 38 60 [2] 24 4f }

  condition:
    any of them
}