rule TTP_XOR_QUAD_CurrentVersionRun_4a40 {
  strings:
    $key_4a40 = { 19 2f [2] 3d 21 [2] 16 0d [2] 38 2f [2] 2c 34 [2] 23 2e [2] 3d 33 [2] 3f 32 [2] 24 34 [2] 38 33 [2] 24 1c }

  condition:
    any of them
}