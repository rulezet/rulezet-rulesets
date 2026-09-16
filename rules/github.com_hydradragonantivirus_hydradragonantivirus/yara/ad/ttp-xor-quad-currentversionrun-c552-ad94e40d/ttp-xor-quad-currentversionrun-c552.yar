rule TTP_XOR_QUAD_CurrentVersionRun_c552 {
  strings:
    $key_c552 = { 96 3d [2] b2 33 [2] 99 1f [2] b7 3d [2] a3 26 [2] ac 3c [2] b2 21 [2] b0 20 [2] ab 26 [2] b7 21 [2] ab 0e }

  condition:
    any of them
}