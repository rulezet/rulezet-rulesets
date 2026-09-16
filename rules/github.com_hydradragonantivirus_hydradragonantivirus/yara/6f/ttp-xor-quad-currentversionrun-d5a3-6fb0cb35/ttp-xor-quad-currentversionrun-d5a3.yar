rule TTP_XOR_QUAD_CurrentVersionRun_d5a3 {
  strings:
    $key_d5a3 = { 86 cc [2] a2 c2 [2] 89 ee [2] a7 cc [2] b3 d7 [2] bc cd [2] a2 d0 [2] a0 d1 [2] bb d7 [2] a7 d0 [2] bb ff }

  condition:
    any of them
}