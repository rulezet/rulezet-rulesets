rule TTP_XOR_QUAD_CurrentVersionRun_c26d {
  strings:
    $key_c26d = { 91 02 [2] b5 0c [2] 9e 20 [2] b0 02 [2] a4 19 [2] ab 03 [2] b5 1e [2] b7 1f [2] ac 19 [2] b0 1e [2] ac 31 }

  condition:
    any of them
}