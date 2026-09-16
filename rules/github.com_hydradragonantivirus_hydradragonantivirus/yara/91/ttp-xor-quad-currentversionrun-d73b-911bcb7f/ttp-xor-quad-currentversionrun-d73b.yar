rule TTP_XOR_QUAD_CurrentVersionRun_d73b {
  strings:
    $key_d73b = { 84 54 [2] a0 5a [2] 8b 76 [2] a5 54 [2] b1 4f [2] be 55 [2] a0 48 [2] a2 49 [2] b9 4f [2] a5 48 [2] b9 67 }

  condition:
    any of them
}