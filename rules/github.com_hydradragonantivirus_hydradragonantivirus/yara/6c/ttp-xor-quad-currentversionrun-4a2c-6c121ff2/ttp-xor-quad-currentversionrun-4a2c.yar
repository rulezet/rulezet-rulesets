rule TTP_XOR_QUAD_CurrentVersionRun_4a2c {
  strings:
    $key_4a2c = { 19 43 [2] 3d 4d [2] 16 61 [2] 38 43 [2] 2c 58 [2] 23 42 [2] 3d 5f [2] 3f 5e [2] 24 58 [2] 38 5f [2] 24 70 }

  condition:
    any of them
}