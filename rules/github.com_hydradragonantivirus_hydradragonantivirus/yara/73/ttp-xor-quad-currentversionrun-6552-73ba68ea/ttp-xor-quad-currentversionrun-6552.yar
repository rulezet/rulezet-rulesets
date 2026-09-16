rule TTP_XOR_QUAD_CurrentVersionRun_6552 {
  strings:
    $key_6552 = { 36 3d [2] 12 33 [2] 39 1f [2] 17 3d [2] 03 26 [2] 0c 3c [2] 12 21 [2] 10 20 [2] 0b 26 [2] 17 21 [2] 0b 0e }

  condition:
    any of them
}