rule TTP_XOR_QUAD_CurrentVersionRun_d04e {
  strings:
    $key_d04e = { 83 21 [2] a7 2f [2] 8c 03 [2] a2 21 [2] b6 3a [2] b9 20 [2] a7 3d [2] a5 3c [2] be 3a [2] a2 3d [2] be 12 }

  condition:
    any of them
}