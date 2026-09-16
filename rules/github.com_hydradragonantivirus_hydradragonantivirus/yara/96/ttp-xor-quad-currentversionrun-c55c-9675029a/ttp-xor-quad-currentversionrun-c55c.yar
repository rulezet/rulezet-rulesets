rule TTP_XOR_QUAD_CurrentVersionRun_c55c {
  strings:
    $key_c55c = { 96 33 [2] b2 3d [2] 99 11 [2] b7 33 [2] a3 28 [2] ac 32 [2] b2 2f [2] b0 2e [2] ab 28 [2] b7 2f [2] ab 00 }

  condition:
    any of them
}