rule TTP_XOR_QUAD_CurrentVersionRun_7e52 {
  strings:
    $key_7e52 = { 2d 3d [2] 09 33 [2] 22 1f [2] 0c 3d [2] 18 26 [2] 17 3c [2] 09 21 [2] 0b 20 [2] 10 26 [2] 0c 21 [2] 10 0e }

  condition:
    any of them
}