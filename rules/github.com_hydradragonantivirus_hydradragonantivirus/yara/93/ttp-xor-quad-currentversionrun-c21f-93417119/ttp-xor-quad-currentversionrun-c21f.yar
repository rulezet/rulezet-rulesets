rule TTP_XOR_QUAD_CurrentVersionRun_c21f {
  strings:
    $key_c21f = { 91 70 [2] b5 7e [2] 9e 52 [2] b0 70 [2] a4 6b [2] ab 71 [2] b5 6c [2] b7 6d [2] ac 6b [2] b0 6c [2] ac 43 }

  condition:
    any of them
}