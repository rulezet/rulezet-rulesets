rule TTP_XOR_QUAD_CurrentVersionRun_c25c {
  strings:
    $key_c25c = { 91 33 [2] b5 3d [2] 9e 11 [2] b0 33 [2] a4 28 [2] ab 32 [2] b5 2f [2] b7 2e [2] ac 28 [2] b0 2f [2] ac 00 }

  condition:
    any of them
}