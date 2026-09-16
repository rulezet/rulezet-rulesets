rule TTP_XOR_QUAD_CurrentVersionRun_d75c {
  strings:
    $key_d75c = { 84 33 [2] a0 3d [2] 8b 11 [2] a5 33 [2] b1 28 [2] be 32 [2] a0 2f [2] a2 2e [2] b9 28 [2] a5 2f [2] b9 00 }

  condition:
    any of them
}