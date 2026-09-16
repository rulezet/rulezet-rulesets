rule TTP_XOR_QUAD_CurrentVersionRun_c5a3 {
  strings:
    $key_c5a3 = { 96 cc [2] b2 c2 [2] 99 ee [2] b7 cc [2] a3 d7 [2] ac cd [2] b2 d0 [2] b0 d1 [2] ab d7 [2] b7 d0 [2] ab ff }

  condition:
    any of them
}