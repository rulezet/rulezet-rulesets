rule TTP_XOR_QUAD_CurrentVersionRun_ce52 {
  strings:
    $key_ce52 = { 9d 3d [2] b9 33 [2] 92 1f [2] bc 3d [2] a8 26 [2] a7 3c [2] b9 21 [2] bb 20 [2] a0 26 [2] bc 21 [2] a0 0e }

  condition:
    any of them
}