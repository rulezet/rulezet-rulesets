rule TTP_XOR_QUAD_CurrentVersionRun_ce22 {
  strings:
    $key_ce22 = { 9d 4d [2] b9 43 [2] 92 6f [2] bc 4d [2] a8 56 [2] a7 4c [2] b9 51 [2] bb 50 [2] a0 56 [2] bc 51 [2] a0 7e }

  condition:
    any of them
}