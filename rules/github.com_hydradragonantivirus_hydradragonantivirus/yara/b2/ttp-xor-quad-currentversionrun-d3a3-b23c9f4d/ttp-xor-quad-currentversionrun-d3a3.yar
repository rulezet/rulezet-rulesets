rule TTP_XOR_QUAD_CurrentVersionRun_d3a3 {
  strings:
    $key_d3a3 = { 80 cc [2] a4 c2 [2] 8f ee [2] a1 cc [2] b5 d7 [2] ba cd [2] a4 d0 [2] a6 d1 [2] bd d7 [2] a1 d0 [2] bd ff }

  condition:
    any of them
}