rule TTP_XOR_QUAD_CurrentVersionRun_4a00 {
  strings:
    $key_4a00 = { 19 6f [2] 3d 61 [2] 16 4d [2] 38 6f [2] 2c 74 [2] 23 6e [2] 3d 73 [2] 3f 72 [2] 24 74 [2] 38 73 [2] 24 5c }

  condition:
    any of them
}