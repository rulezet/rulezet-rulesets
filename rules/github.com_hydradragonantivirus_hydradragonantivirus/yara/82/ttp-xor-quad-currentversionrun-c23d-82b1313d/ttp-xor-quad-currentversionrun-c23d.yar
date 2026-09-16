rule TTP_XOR_QUAD_CurrentVersionRun_c23d {
  strings:
    $key_c23d = { 91 52 [2] b5 5c [2] 9e 70 [2] b0 52 [2] a4 49 [2] ab 53 [2] b5 4e [2] b7 4f [2] ac 49 [2] b0 4e [2] ac 61 }

  condition:
    any of them
}