rule TTP_XOR_QUAD_CurrentVersionRun_d05c {
  strings:
    $key_d05c = { 83 33 [2] a7 3d [2] 8c 11 [2] a2 33 [2] b6 28 [2] b9 32 [2] a7 2f [2] a5 2e [2] be 28 [2] a2 2f [2] be 00 }

  condition:
    any of them
}