rule TTP_XOR_QUAD_CurrentVersionRun_4a11 {
  strings:
    $key_4a11 = { 19 7e [2] 3d 70 [2] 16 5c [2] 38 7e [2] 2c 65 [2] 23 7f [2] 3d 62 [2] 3f 63 [2] 24 65 [2] 38 62 [2] 24 4d }

  condition:
    any of them
}