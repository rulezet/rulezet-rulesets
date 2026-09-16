rule TTP_XOR_QUAD_CurrentVersionRun_1852 {
  strings:
    $key_1852 = { 4b 3d [2] 6f 33 [2] 44 1f [2] 6a 3d [2] 7e 26 [2] 71 3c [2] 6f 21 [2] 6d 20 [2] 76 26 [2] 6a 21 [2] 76 0e }

  condition:
    any of them
}