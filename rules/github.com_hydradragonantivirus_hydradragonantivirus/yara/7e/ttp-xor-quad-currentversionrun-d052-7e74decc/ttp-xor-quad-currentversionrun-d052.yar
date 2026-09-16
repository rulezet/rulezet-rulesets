rule TTP_XOR_QUAD_CurrentVersionRun_d052 {
  strings:
    $key_d052 = { 83 3d [2] a7 33 [2] 8c 1f [2] a2 3d [2] b6 26 [2] b9 3c [2] a7 21 [2] a5 20 [2] be 26 [2] a2 21 [2] be 0e }

  condition:
    any of them
}