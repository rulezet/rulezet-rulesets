rule TTP_XOR_QUAD_CurrentVersionRun_c24d {
  strings:
    $key_c24d = { 91 22 [2] b5 2c [2] 9e 00 [2] b0 22 [2] a4 39 [2] ab 23 [2] b5 3e [2] b7 3f [2] ac 39 [2] b0 3e [2] ac 11 }

  condition:
    any of them
}