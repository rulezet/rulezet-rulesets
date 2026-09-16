rule TTP_XOR_QUAD_CurrentVersionRun_c22d {
  strings:
    $key_c22d = { 91 42 [2] b5 4c [2] 9e 60 [2] b0 42 [2] a4 59 [2] ab 43 [2] b5 5e [2] b7 5f [2] ac 59 [2] b0 5e [2] ac 71 }

  condition:
    any of them
}