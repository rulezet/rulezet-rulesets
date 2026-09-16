rule TTP_XOR_QUAD_CurrentVersionRun_daa3 {
  strings:
    $key_daa3 = { 89 cc [2] ad c2 [2] 86 ee [2] a8 cc [2] bc d7 [2] b3 cd [2] ad d0 [2] af d1 [2] b4 d7 [2] a8 d0 [2] b4 ff }

  condition:
    any of them
}