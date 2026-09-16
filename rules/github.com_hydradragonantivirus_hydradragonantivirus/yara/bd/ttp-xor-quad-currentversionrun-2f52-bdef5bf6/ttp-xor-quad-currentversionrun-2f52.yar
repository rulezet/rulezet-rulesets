rule TTP_XOR_QUAD_CurrentVersionRun_2f52 {
  strings:
    $key_2f52 = { 7c 3d [2] 58 33 [2] 73 1f [2] 5d 3d [2] 49 26 [2] 46 3c [2] 58 21 [2] 5a 20 [2] 41 26 [2] 5d 21 [2] 41 0e }

  condition:
    any of them
}