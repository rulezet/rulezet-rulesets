rule TTP_XOR_QUAD_CurrentVersionRun_c252 {
  strings:
    $key_c252 = { 91 3d [2] b5 33 [2] 9e 1f [2] b0 3d [2] a4 26 [2] ab 3c [2] b5 21 [2] b7 20 [2] ac 26 [2] b0 21 [2] ac 0e }

  condition:
    any of them
}