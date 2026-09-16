rule TTP_XOR_QUAD_CurrentVersionRun_4a51 {
  strings:
    $key_4a51 = { 19 3e [2] 3d 30 [2] 16 1c [2] 38 3e [2] 2c 25 [2] 23 3f [2] 3d 22 [2] 3f 23 [2] 24 25 [2] 38 22 [2] 24 0d }

  condition:
    any of them
}