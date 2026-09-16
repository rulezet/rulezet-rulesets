rule TTP_XOR_QUAD_CurrentVersionRun_4a50 {
  strings:
    $key_4a50 = { 19 3f [2] 3d 31 [2] 16 1d [2] 38 3f [2] 2c 24 [2] 23 3e [2] 3d 23 [2] 3f 22 [2] 24 24 [2] 38 23 [2] 24 0c }

  condition:
    any of them
}