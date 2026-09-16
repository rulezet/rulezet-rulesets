rule TTP_XOR_QUAD_CurrentVersionRun_d2a3 {
  strings:
    $key_d2a3 = { 81 cc [2] a5 c2 [2] 8e ee [2] a0 cc [2] b4 d7 [2] bb cd [2] a5 d0 [2] a7 d1 [2] bc d7 [2] a0 d0 [2] bc ff }

  condition:
    any of them
}