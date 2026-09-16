rule TTP_XOR_QUAD_CurrentVersionRun_c21a {
  strings:
    $key_c21a = { 91 75 [2] b5 7b [2] 9e 57 [2] b0 75 [2] a4 6e [2] ab 74 [2] b5 69 [2] b7 68 [2] ac 6e [2] b0 69 [2] ac 46 }

  condition:
    any of them
}