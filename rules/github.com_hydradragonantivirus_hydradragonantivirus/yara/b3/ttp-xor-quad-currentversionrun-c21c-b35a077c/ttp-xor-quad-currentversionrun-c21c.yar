rule TTP_XOR_QUAD_CurrentVersionRun_c21c {
  strings:
    $key_c21c = { 91 73 [2] b5 7d [2] 9e 51 [2] b0 73 [2] a4 68 [2] ab 72 [2] b5 6f [2] b7 6e [2] ac 68 [2] b0 6f [2] ac 40 }

  condition:
    any of them
}