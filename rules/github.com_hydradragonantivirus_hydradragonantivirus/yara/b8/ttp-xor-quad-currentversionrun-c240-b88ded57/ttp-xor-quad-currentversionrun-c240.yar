rule TTP_XOR_QUAD_CurrentVersionRun_c240 {
  strings:
    $key_c240 = { 91 2f [2] b5 21 [2] 9e 0d [2] b0 2f [2] a4 34 [2] ab 2e [2] b5 33 [2] b7 32 [2] ac 34 [2] b0 33 [2] ac 1c }

  condition:
    any of them
}