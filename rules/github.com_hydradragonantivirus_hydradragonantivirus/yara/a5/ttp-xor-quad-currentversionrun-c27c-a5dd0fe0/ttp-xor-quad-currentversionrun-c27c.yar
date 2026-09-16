rule TTP_XOR_QUAD_CurrentVersionRun_c27c {
  strings:
    $key_c27c = { 91 13 [2] b5 1d [2] 9e 31 [2] b0 13 [2] a4 08 [2] ab 12 [2] b5 0f [2] b7 0e [2] ac 08 [2] b0 0f [2] ac 20 }

  condition:
    any of them
}