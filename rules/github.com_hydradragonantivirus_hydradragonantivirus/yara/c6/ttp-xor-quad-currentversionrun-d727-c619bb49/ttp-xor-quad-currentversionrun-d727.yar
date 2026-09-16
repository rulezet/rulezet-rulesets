rule TTP_XOR_QUAD_CurrentVersionRun_d727 {
  strings:
    $key_d727 = { 84 48 [2] a0 46 [2] 8b 6a [2] a5 48 [2] b1 53 [2] be 49 [2] a0 54 [2] a2 55 [2] b9 53 [2] a5 54 [2] b9 7b }

  condition:
    any of them
}