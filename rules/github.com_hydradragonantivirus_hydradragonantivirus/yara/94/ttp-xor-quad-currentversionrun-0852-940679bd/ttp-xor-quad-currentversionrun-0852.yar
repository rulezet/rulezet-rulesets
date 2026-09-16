rule TTP_XOR_QUAD_CurrentVersionRun_0852 {
  strings:
    $key_0852 = { 5b 3d [2] 7f 33 [2] 54 1f [2] 7a 3d [2] 6e 26 [2] 61 3c [2] 7f 21 [2] 7d 20 [2] 66 26 [2] 7a 21 [2] 66 0e }

  condition:
    any of them
}