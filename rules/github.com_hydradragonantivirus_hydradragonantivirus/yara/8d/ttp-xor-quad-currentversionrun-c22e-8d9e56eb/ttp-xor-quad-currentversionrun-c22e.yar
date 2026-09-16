rule TTP_XOR_QUAD_CurrentVersionRun_c22e {
  strings:
    $key_c22e = { 91 41 [2] b5 4f [2] 9e 63 [2] b0 41 [2] a4 5a [2] ab 40 [2] b5 5d [2] b7 5c [2] ac 5a [2] b0 5d [2] ac 72 }

  condition:
    any of them
}