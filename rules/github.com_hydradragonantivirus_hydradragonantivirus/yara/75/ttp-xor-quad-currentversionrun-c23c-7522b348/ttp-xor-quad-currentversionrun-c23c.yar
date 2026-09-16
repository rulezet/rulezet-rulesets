rule TTP_XOR_QUAD_CurrentVersionRun_c23c {
  strings:
    $key_c23c = { 91 53 [2] b5 5d [2] 9e 71 [2] b0 53 [2] a4 48 [2] ab 52 [2] b5 4f [2] b7 4e [2] ac 48 [2] b0 4f [2] ac 60 }

  condition:
    any of them
}