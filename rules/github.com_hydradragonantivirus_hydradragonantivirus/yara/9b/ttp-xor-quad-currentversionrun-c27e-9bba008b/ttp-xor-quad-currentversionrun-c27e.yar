rule TTP_XOR_QUAD_CurrentVersionRun_c27e {
  strings:
    $key_c27e = { 91 11 [2] b5 1f [2] 9e 33 [2] b0 11 [2] a4 0a [2] ab 10 [2] b5 0d [2] b7 0c [2] ac 0a [2] b0 0d [2] ac 22 }

  condition:
    any of them
}