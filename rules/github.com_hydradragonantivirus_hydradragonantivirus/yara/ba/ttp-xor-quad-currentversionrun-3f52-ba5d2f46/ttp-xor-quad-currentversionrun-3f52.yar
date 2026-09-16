rule TTP_XOR_QUAD_CurrentVersionRun_3f52 {
  strings:
    $key_3f52 = { 6c 3d [2] 48 33 [2] 63 1f [2] 4d 3d [2] 59 26 [2] 56 3c [2] 48 21 [2] 4a 20 [2] 51 26 [2] 4d 21 [2] 51 0e }

  condition:
    any of them
}