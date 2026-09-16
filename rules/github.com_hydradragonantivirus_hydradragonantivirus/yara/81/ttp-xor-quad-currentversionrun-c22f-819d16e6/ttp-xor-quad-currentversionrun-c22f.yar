rule TTP_XOR_QUAD_CurrentVersionRun_c22f {
  strings:
    $key_c22f = { 91 40 [2] b5 4e [2] 9e 62 [2] b0 40 [2] a4 5b [2] ab 41 [2] b5 5c [2] b7 5d [2] ac 5b [2] b0 5c [2] ac 73 }

  condition:
    any of them
}