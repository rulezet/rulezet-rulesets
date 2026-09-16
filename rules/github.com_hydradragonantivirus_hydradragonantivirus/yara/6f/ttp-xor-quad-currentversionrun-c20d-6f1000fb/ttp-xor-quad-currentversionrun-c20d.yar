rule TTP_XOR_QUAD_CurrentVersionRun_c20d {
  strings:
    $key_c20d = { 91 62 [2] b5 6c [2] 9e 40 [2] b0 62 [2] a4 79 [2] ab 63 [2] b5 7e [2] b7 7f [2] ac 79 [2] b0 7e [2] ac 51 }

  condition:
    any of them
}