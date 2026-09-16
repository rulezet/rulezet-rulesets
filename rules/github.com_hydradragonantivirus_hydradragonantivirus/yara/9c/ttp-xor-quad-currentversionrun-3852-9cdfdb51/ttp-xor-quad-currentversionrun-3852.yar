rule TTP_XOR_QUAD_CurrentVersionRun_3852 {
  strings:
    $key_3852 = { 6b 3d [2] 4f 33 [2] 64 1f [2] 4a 3d [2] 5e 26 [2] 51 3c [2] 4f 21 [2] 4d 20 [2] 56 26 [2] 4a 21 [2] 56 0e }

  condition:
    any of them
}