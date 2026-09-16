rule TTP_XOR_QUAD_CurrentVersionRun_531c {
  strings:
    $key_531c = { 00 73 [2] 24 7d [2] 0f 51 [2] 21 73 [2] 35 68 [2] 3a 72 [2] 24 6f [2] 26 6e [2] 3d 68 [2] 21 6f [2] 3d 40 }

  condition:
    any of them
}